/*
 * Copyright (c) 2023-24 Harman International
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.oauth2.server.core.service;

import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ScopePreference;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ScopeRoleMapping;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Evaluates per-IDP external-role → internal-scope mapping rules against the
 * current IDP
 * claims on every federated login.
 *
 * <p>
 * All mappings are fully property-driven (configured in tenant properties
 * files).
 * No database or API calls are made by this service, other than the one-time
 * scope
 * re-fetch fallback for a brand-new federated user (see
 * {@link #refetchUserScope}).
 *
 * <p>
 * Resolution order, per the requirement spec (points 9 and 10):
 * <ol>
 * <li><b>Point 9</b> — the requested-scope gate. If
 * {@code uidamClientRequestedScope} is
 * non-blank, it must share at least one value with {@code uidamUserScope}
 * itself
 * ("no overlap → throw INVALID_SCOPE, no need to check further"). This is
 * checked
 * <i>before</i> {@code scopeRoleMappings} is even evaluated, and is independent
 * of
 * {@link ScopePreference}.</li>
 * <li><b>Rule 1</b> — {@link #resolveScopeRoleMapping}: matches
 * {@code ExternalIDPTokenRoles}
 * against the configured {@code scopeRoleMappings}, grouping matched rules'
 * scopes by
 * their own {@link ScopePreference}.</li>
 * <li><b>Rule 2</b> — {@link #resolveFinalScope}: resolves the final scope per
 * preference —
 * INTERNAL ignores the mapping entirely (10.1.2); EXTERNAL grants exactly the
 * matched
 * rule's mapped scopes, replacing the request (10.2.2); BOTH grants the union
 * of both
 * (10.3.3); EXTERNAL/BOTH configured but never matched throws
 * (10.2.3/10.3.2).</li>
 * </ol>
 */
@Service
public class ScopeRoleClaimMappingService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ScopeRoleClaimMappingService.class);

    private static final String DEFAULT_ROLE_CLAIM_KEY = "groups";

    private static final String[] EXTERNAL_IDP_ROLE_CLAIM_KEY_SEPARATORS = new String[] { " ", "," };

    private final UserManagementClient userManagementClient;

    private static final String NO_OVERLAP_ERROR_MESSAGE = "Requested scope has no overlap with user's UIDAM scope";

    /**
     * Standard OIDC/id_token-related scopes. These control id_token content/claims (e.g.
     * requesting an id_token, or which standard claims get added to it) and are not
     * application-level UIDAM authorization scopes, so they must be excluded before any
     * scope-overlap/matching check against {@code uidamUserScope}.
     */
    private static final Set<String> OIDC_SCOPES = Set.of(
            OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, OidcScopes.ADDRESS, OidcScopes.PHONE);

    public ScopeRoleClaimMappingService(UserManagementClient userManagementClient) {
        this.userManagementClient = userManagementClient;
    }

    /**
     * Single entry point for dynamic external-role → internal-scope mapping on a
     * federated login.
     * Updates {@code userDetailsResponse} with the final resolved scopes.
     * 
     * <p>
     * Master checkpoint: this entire pipeline is opt-in per IDP, gated by
     * {@link #isScopeRoleMappingEnabled(ExternalIdpRegisteredClient)}. When
     * disabled, the mapping
     * is skipped entirely and {@code userDetailsResponse} is left untouched
     * (existing/legacy
     * behavior for IDPs that haven't opted in).
     *
     * <p>
     * No-op when {@code userDetailsResponse} is {@code null}.
     *
     * @param extIdpRegClient           the external IDP client configuration
     *                                  (scopeRoleMappings, roleClaimKey)
     * @param externalIdpTokenClaims    the raw claims/attributes received from the
     *                                  external IDP
     * @param uidamClientRequestedScope the Requested Scope — the client's requested
     *                                  {@code scope}
     *                                  (i.e.
     *                                  {@code claimsBuilder.build().getClaim(OAuth2ParameterNames.SCOPE)});
     *                                  may be empty/null
     * @param userDetailsResponse       the user details whose scopes are
     *                                  resolved/updated in place
     * @throws OAuth2AuthenticationException if the Requested Scope has no overlap
     *                                       with
     *                                       {@code uidamUserScope} (point 9), or a
     *                                       matched preference's resolution fails
     *                                       (point 10) — see {@link #resolveScopes}
     */
    public void applyScopeRoleMapping(ExternalIdpRegisteredClient extIdpRegClient,
            Map<String, Object> externalIdpTokenClaims,
            Set<String> uidamClientRequestedScope,
            UserDetailsResponse userDetailsResponse) {
        Set<String> resolvedUidamScope = null;
        if (userDetailsResponse == null) {
            LOGGER.debug("applyScopeRoleMapping: userDetailsResponse is null, skipping");
            return;
        }
        // Application-only requested scope: excludes openid/profile/email/address/phone, which are
        // id_token/OIDC scopes, not UIDAM application authorization scopes, and must not be checked
        // against uidamUserScope below.
        Set<String> uidamClientRequestedAppScope = excludeOidcScopes(uidamClientRequestedScope);
        Set<String> uidamUserScope = resolveNonEmptyUserScope(userDetailsResponse);
        ScopePreference scopePreference = extIdpRegClient.getScopePreference();
        String registrationId = extIdpRegClient.getRegistrationId();
        LOGGER.debug("applyScopeRoleMapping: registrationId='{}', scopePreference={}, "
                + "uidamClientRequestedAppScope={}, uidamUserScope={}",
                registrationId,
                scopePreference, uidamClientRequestedAppScope, uidamUserScope);
        if (ScopePreference.INTERNAL.equals(scopePreference)) {
            resolvedUidamScope = resolveScopeForInternalScopePreference(uidamClientRequestedAppScope, uidamUserScope);
        } else if (ScopePreference.EXTERNAL.equals(scopePreference)) {
            resolvedUidamScope = resolveScopeForExternalScopePreference(extIdpRegClient, externalIdpTokenClaims);
            validateExternalPreferenceScope(resolvedUidamScope, uidamClientRequestedAppScope, uidamUserScope);
        } else if (ScopePreference.BOTH.equals(scopePreference)) {
            resolvedUidamScope = resolveScopeForBothScopePreference(extIdpRegClient, externalIdpTokenClaims,
                    uidamClientRequestedAppScope, uidamUserScope);
        }
        LOGGER.debug("applyScopeRoleMapping: registrationId='{}', scopePreference={}, "
                + "resolvedUidamScope={}", registrationId, scopePreference, resolvedUidamScope);
        if (CollectionUtils.isEmpty(resolvedUidamScope)) {
            LOGGER.error("resolvedUidamScope is empty, throwing INVALID_SCOPE");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(CustomOauth2TokenGenErrorCodes.INVALID_SCOPE.name(),
                            "Resolved UIDAM scope is empty", null));
        }
        userDetailsResponse.setScopes(resolvedUidamScope);
    }

    /**
     * Filters out standard OIDC/id_token-related scopes ({@value OidcScopes#OPENID},
     * {@value OidcScopes#PROFILE}, {@value OidcScopes#EMAIL}, {@value OidcScopes#ADDRESS},
     * {@value OidcScopes#PHONE}) from the client's requested scope, leaving only
     * application-specific (UIDAM) scopes.
     *
     * @param uidamClientRequestedScope the raw requested scope (may be {@code null}/empty)
     * @return a new, independent Set containing only the non-OIDC application scopes;
     *         empty if the input is {@code null}/empty
     */
    private Set<String> excludeOidcScopes(Set<String> uidamClientRequestedScope) {
        if (CollectionUtils.isEmpty(uidamClientRequestedScope)) {
            return Collections.emptySet();
        }
        return uidamClientRequestedScope.stream()
                .filter(scope -> !OIDC_SCOPES.contains(scope))
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Returns the user's UIDAM scope, re-fetching once from user-management if it arrives
     * empty (see {@link #refetchUserScope}) before giving up.
     *
     * @param userDetailsResponse the user details to resolve scope for
     * @return the resolved, non-empty UIDAM scope
     * @throws OAuth2AuthenticationException if the scope is still null/empty after the re-fetch
     */
    private Set<String> resolveNonEmptyUserScope(UserDetailsResponse userDetailsResponse) {
        Set<String> uidamUserScope = userDetailsResponse.getScopes();
        if (CollectionUtils.isEmpty(uidamUserScope)) {
            uidamUserScope = refetchUserScope(userDetailsResponse);
            if (CollectionUtils.isEmpty(uidamUserScope)) {
                LOGGER.error("applyScopeRoleMapping: uidamUserScope is still empty after re-fetch, "
                        + "throwing INVALID_SCOPE");
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(CustomOauth2TokenGenErrorCodes.INVALID_SCOPE.name(),
                                "User's UIDAM scope is empty", null));
            }
        }
        return uidamUserScope;
    }

    /**
     * Validates the EXTERNAL-preference resolved scope: throws if it's empty (no rule matched),
     * or if a non-blank Requested Scope isn't fully contained within it.
     */
    private void validateExternalPreferenceScope(Set<String> resolvedUidamScope,
            Set<String> uidamClientRequestedScope, Set<String> uidamUserScope) {
        if (CollectionUtils.isEmpty(resolvedUidamScope)) {
            LOGGER.error(
                    "resolvedUidamScope : {}, uidamUserScope : {}, requested scope {} has no overlap "
                            + "with user's UIDAM user scope {}, throwing INVALID_SCOPE",
                    resolvedUidamScope, uidamUserScope, uidamClientRequestedScope, uidamUserScope);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(CustomOauth2TokenGenErrorCodes.INVALID_SCOPE.name(),
                            NO_OVERLAP_ERROR_MESSAGE, null));
        }
        if (!CollectionUtils.isEmpty(uidamClientRequestedScope)
                && !resolvedUidamScope.containsAll(uidamClientRequestedScope)) {
            LOGGER.error(
                    "resolvedUidamScope : {}, uidamUserScope : {}, requested scope {} does not match "
                            + "user's UIDAM user scope {}, throwing INVALID_SCOPE",
                    resolvedUidamScope, uidamUserScope, uidamClientRequestedScope, uidamClientRequestedScope);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(CustomOauth2TokenGenErrorCodes.INVALID_SCOPE.name(),
                            "Requested scope does not match user's UIDAM scope", null));
        }
    }

    /**
     * Resolves the final scope for the BOTH preference: union of the internal scope and the
     * matched external scope (merged in only when the internal scope is non-empty).
     *
     * @throws OAuth2AuthenticationException if no external rule matched (empty resolved external scope)
     */
    private Set<String> resolveScopeForBothScopePreference(ExternalIdpRegisteredClient extIdpRegClient,
            Map<String, Object> externalIdpTokenClaims, Set<String> uidamClientRequestedScope,
            Set<String> uidamUserScope) {
        Set<String> resolvedUidamScope = resolveScopeForInternalScopePreference(uidamClientRequestedScope,
                uidamUserScope);
        Set<String> resolvedExternalUidamScope = resolveScopeForExternalScopePreference(extIdpRegClient,
                externalIdpTokenClaims);
        if (CollectionUtils.isEmpty(resolvedExternalUidamScope)) {
            LOGGER.error(
                    "resolvedExternalUidamScope : {}, uidamUserScope : {}, requested scope {} has no overlap "
                            + "with user's UIDAM user scope {}, throwing INVALID_SCOPE",
                    resolvedExternalUidamScope, uidamUserScope, uidamClientRequestedScope, uidamUserScope);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(CustomOauth2TokenGenErrorCodes.INVALID_SCOPE.name(),
                            NO_OVERLAP_ERROR_MESSAGE, null));
        } else if (!CollectionUtils.isEmpty(resolvedUidamScope)) {
            resolvedUidamScope.addAll(resolvedExternalUidamScope);
        }
        return resolvedUidamScope;
    }

    private Set<String> resolveScopeForInternalScopePreference(Set<String> uidamClientRequestedScope,
            Set<String> uidamUserScope) {
        if (!CollectionUtils.isEmpty(uidamClientRequestedScope)) {
            if (!uidamUserScope.containsAll(uidamClientRequestedScope)) {
                LOGGER.error(
                        "Client requested scope {} does not match user's UIDAM user scope {}, throwing INVALID_SCOPE",
                        uidamClientRequestedScope, uidamUserScope);
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(CustomOauth2TokenGenErrorCodes.INVALID_SCOPE.name(),
                                NO_OVERLAP_ERROR_MESSAGE, null));
            }
        }
        return uidamUserScope;
    }

    private Set<String> resolveScopeForExternalScopePreference(ExternalIdpRegisteredClient extIdpRegClient,
            Map<String, Object> externalIdpTokenClaims) {
        String roleClaimKey = resolveRoleClaimKey(extIdpRegClient);
        List<ScopeRoleMapping> scopeRoleMappingsConfigList = extIdpRegClient.getScopeRoleMappings();
        if (CollectionUtils.isEmpty(scopeRoleMappingsConfigList)) {
            LOGGER.error(" scopePreference=EXTERNAL, "
                    + "no scopeRoleMappingsConfigList found, throwing INVALID_SCOPE");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(CustomOauth2TokenGenErrorCodes.INVALID_SCOPE.name(),
                            "No scopeRoleMappingsConfigList found", null));
        }
        return findMatchingInternalScope(extIdpRegClient, scopeRoleMappingsConfigList, externalIdpTokenClaims,
                roleClaimKey);
    }

    /**
     * Resolves the external-IDP role claim key to use, falling back to
     * {@value #DEFAULT_ROLE_CLAIM_KEY} when not configured.
     *
     * @throws OAuth2AuthenticationException if the resolved key is still blank
     */
    private String resolveRoleClaimKey(ExternalIdpRegisteredClient extIdpRegClient) {
        String roleClaimKey = Optional.ofNullable(extIdpRegClient.getRoleClaimKey())
                .filter(key -> !key.isBlank())
                .orElse(DEFAULT_ROLE_CLAIM_KEY);
        if (!StringUtils.hasText(roleClaimKey)) {
            LOGGER.error(" scopePreference=EXTERNAL, "
                    + "roleClaimKey is not set, throwing INVALID_SCOPE");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(CustomOauth2TokenGenErrorCodes.INVALID_SCOPE.name(),
                            "roleClaimKey is not set", null));
        }
        return roleClaimKey;
    }

    /**
     * Finds the first {@link ScopeRoleMapping} whose external role values fully cover the
     * IDP token's role claim, returning its internal scope values.
     *
     * @return the matched mapping's internal scope values, or {@code null} if none match
     */
    private Set<String> findMatchingInternalScope(ExternalIdpRegisteredClient extIdpRegClient,
            List<ScopeRoleMapping> scopeRoleMappingsConfigList, Map<String, Object> externalIdpTokenClaims,
            String roleClaimKey) {
        for (ScopeRoleMapping scopeRoleMapping : scopeRoleMappingsConfigList) {
            Set<String> externalRoleValues = scopeRoleMapping.getExternalRoleValues();
            LOGGER.debug("resolveScopeForExternalScopePreference: registrationId='{}', scopeRoleMapping={}",
                    extIdpRegClient.getRegistrationId(), scopeRoleMapping);
            Set<String> externalIdpTokenRoles = extractRoleValues(
                    externalIdpTokenClaims != null ? externalIdpTokenClaims.get(roleClaimKey) : null);
            LOGGER.debug("resolveScopeForExternalScopePreference: registrationId='{}', externalIdpTokenRoles={}",
                    extIdpRegClient.getRegistrationId(), externalIdpTokenRoles);
            if (isRoleMatch(externalIdpTokenRoles, externalRoleValues)) {
                return scopeRoleMapping.getInternalScopeValues();
            }
        }
        return Set.of();
    }

    /**
     * Checks whether the configured external role values fully cover the IDP token's roles
     * (both non-empty, and {@code externalRoleValues} contains all of {@code externalIdpTokenRoles}).
     */
    private boolean isRoleMatch(Set<String> externalIdpTokenRoles, Set<String> externalRoleValues) {
        return !CollectionUtils.isEmpty(externalIdpTokenRoles) && !CollectionUtils.isEmpty(externalRoleValues)
                && externalRoleValues.containsAll(externalIdpTokenRoles);
    }

    /**
     * Extracts the IDP role claim value as a flat {@code Set<String>}.
     * Handles List, String, and null defensively.
     */
    private Set<String> extractRoleValues(Object roleClaimValue) {
        if (roleClaimValue == null) {
            LOGGER.debug("extractRoleValues: roleClaimValue is null, returning empty set");
            return Set.of();
        }
        if (roleClaimValue instanceof Collection<?> roleClaimValues) {
            LOGGER.debug("extractRoleValues: roleClaimValue is a Collection with {} item(s): {}",
                    roleClaimValues.size(), roleClaimValues);
            Set<String> extractedRoleValues = new HashSet<>();
            for (Object roleValueItem : roleClaimValues) {
                if (roleValueItem != null) {
                    extractedRoleValues.add(roleValueItem.toString().trim());
                }
            }
            LOGGER.debug("extractRoleValues: extractedRoleValues={}", extractedRoleValues);
            return Collections.unmodifiableSet(extractedRoleValues);
        }
        if (roleClaimValue instanceof String roleClaimValueAsString) {
            String externalIdpScopeRoleSeperator = Arrays.stream(EXTERNAL_IDP_ROLE_CLAIM_KEY_SEPARATORS)
                    .filter(roleClaimValueAsString::contains)
                    .findFirst()
                    .orElse(EXTERNAL_IDP_ROLE_CLAIM_KEY_SEPARATORS[0]);
            Set<String> extractedRoleValues = Arrays.stream(
                    roleClaimValueAsString.split(externalIdpScopeRoleSeperator))
                    .map(String::trim)
                    .filter(role -> !role.isEmpty())
                    .collect(Collectors.toUnmodifiableSet());
            LOGGER.debug("extractRoleValues: roleClaimValue is a String='{}', extractedRoleValues={}",
                    roleClaimValueAsString, extractedRoleValues);
            return extractedRoleValues;
        }
        LOGGER.warn("Unexpected role claim type: {}. Falling back to toString().", roleClaimValue.getClass().getName());
        Set<String> fallbackRoleValues = Set.of(roleClaimValue.toString().trim());
        LOGGER.debug("extractRoleValues: fallbackRoleValues={}", fallbackRoleValues);
        return fallbackRoleValues;
    }

    /**
     * Re-fetches the user's scopes from user-management via {@code getUserDetailsByUsername}, which
     * resolves scopes from the user's granted roles. Used as a one-time fallback when
     * {@code userDetailsResponse} arrives with no scopes - the case for a federated user who was
     * just registered in this same login (the create-user response only carries roles, not their
     * resolved scopes). Also updates {@code userDetailsResponse} in place so callers observe the
     * refreshed scopes too.
     *
     * @param userDetailsResponse the user details response missing scopes; its username is used
     *         to re-fetch
     * @return the refetched scopes, or {@code null}/empty if user-management still has none
     */
    private Set<String> refetchUserScope(UserDetailsResponse userDetailsResponse) {
        LOGGER.debug("applyScopeRoleMapping: uidamUserScope missing for username='{}' - likely a newly "
                + "registered federated user whose roles have not yet been resolved to scopes - "
                + "re-fetching from user-management", userDetailsResponse.getUserName());
        UserDetailsResponse refetched = userManagementClient.getUserDetailsByUsername(
                userDetailsResponse.getUserName(), null);
        Set<String> refetchedScope = refetched != null ? refetched.getScopes() : null;
        userDetailsResponse.setScopes(refetchedScope);
        return refetchedScope;
    }

}