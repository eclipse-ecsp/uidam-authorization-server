/*
 * Copyright (c) 2023-24 Harman International
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.oauth2.server.core.service;

import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ScopePreference;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ScopeRoleMapping;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link ScopeRoleClaimMappingService} — covers the empty-scope
 * re-fetch gate, the INTERNAL/EXTERNAL/BOTH {@link ScopePreference} resolution rules
 * in {@code applyScopeRoleMapping}, and the {@code groups} claim extraction logic.
 */
@ExtendWith(MockitoExtension.class)
class ScopeRoleClaimMappingServiceTest {

    @Mock
    private UserManagementClient userManagementClient;

    private ScopeRoleClaimMappingService service;

    @BeforeEach
    void setUp() {
        service = new ScopeRoleClaimMappingService(userManagementClient);
    }

    // ── userDetailsResponse == null ─────────────────────────────────────────

    @Test
    void applyScopeRoleMapping_nullUserDetailsResponse_noOp() {
        ExternalIdpRegisteredClient client = internalClient();
        service.applyScopeRoleMapping(client, Map.of(), Set.of(), null);
        // no exception, no-op
    }

    // ── empty-scope re-fetch gate ────────────────────────────────────────────

    @Test
    void applyScopeRoleMapping_emptyUserScope_refetchSucceeds_usesRefetchedScope() {
        ExternalIdpRegisteredClient client = internalClient();
        UserDetailsResponse userDetailsResponse = userWithScopes();
        userDetailsResponse.setUserName("testUser");
        UserDetailsResponse refetched = userWithScopes("SelfManage");
        doReturn(refetched).when(userManagementClient).getUserDetailsByUsername("testUser", null);

        service.applyScopeRoleMapping(client, Map.of(), Set.of(), userDetailsResponse);

        assertEquals(Set.of("SelfManage"), userDetailsResponse.getScopes());
        verify(userManagementClient).getUserDetailsByUsername("testUser", null);
    }

    @Test
    void applyScopeRoleMapping_emptyUserScope_refetchStillEmpty_throwsInvalidScope() {
        ExternalIdpRegisteredClient client = internalClient();
        UserDetailsResponse userDetailsResponse = userWithScopes();
        userDetailsResponse.setUserName("testUser");
        doReturn(userWithScopes()).when(userManagementClient).getUserDetailsByUsername("testUser", null);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> service.applyScopeRoleMapping(client, Map.of(), Set.of(), userDetailsResponse));
        assertEquals("INVALID_SCOPE", exception.getError().getErrorCode());
    }

    @Test
    void applyScopeRoleMapping_emptyUserScope_refetchReturnsNull_throwsInvalidScope() {
        ExternalIdpRegisteredClient client = internalClient();
        UserDetailsResponse userDetailsResponse = userWithScopes();
        userDetailsResponse.setUserName("testUser");
        doReturn(null).when(userManagementClient).getUserDetailsByUsername("testUser", null);

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> service.applyScopeRoleMapping(client, Map.of(), Set.of(), userDetailsResponse));
        assertEquals("INVALID_SCOPE", exception.getError().getErrorCode());
    }

    // ── INTERNAL preference (10.1) ───────────────────────────────────────────

    @Test
    void applyScopeRoleMapping_internalPreference_noRequestedScope_usesUserScope() {
        ExternalIdpRegisteredClient client = internalClient();
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage", "SelfUserManage");

        service.applyScopeRoleMapping(client, Map.of(), Set.of(), userDetailsResponse);

        assertEquals(Set.of("SelfManage", "SelfUserManage"), userDetailsResponse.getScopes());
    }

    @Test
    void applyScopeRoleMapping_internalPreference_requestedScopeSubsetOfUserScope_succeeds() {
        ExternalIdpRegisteredClient client = internalClient();
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage", "SelfUserManage");

        service.applyScopeRoleMapping(client, Map.of(), Set.of("SelfManage"), userDetailsResponse);

        assertEquals(Set.of("SelfManage", "SelfUserManage"), userDetailsResponse.getScopes());
    }

    @Test
    void applyScopeRoleMapping_internalPreference_requestedScopeNotSubset_throwsInvalidScope() {
        ExternalIdpRegisteredClient client = internalClient();
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> service.applyScopeRoleMapping(client, Map.of(), Set.of("OtherScope"), userDetailsResponse));
        assertEquals("INVALID_SCOPE", exception.getError().getErrorCode());
    }

    // ── EXTERNAL preference (10.2) ───────────────────────────────────────────

    @Test
    void applyScopeRoleMapping_externalPreference_roleMatches_resolvesMappedScope() {
        ExternalIdpRegisteredClient client = externalClient(rule("VWAG_STORE_PRE_GROUP_DEV", "IgniteStoreSeller"));
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = Map.of("groups", "VWAG_STORE_PRE_GROUP_DEV");

        service.applyScopeRoleMapping(client, claims, Set.of(), userDetailsResponse);

        assertEquals(Set.of("IgniteStoreSeller"), userDetailsResponse.getScopes());
    }

    @Test
    void applyScopeRoleMapping_externalPreference_noRuleMatches_throwsInvalidScope() {
        ExternalIdpRegisteredClient client = externalClient(rule("VWAG_STORE_PRE_GROUP_DEV", "IgniteStoreSeller"));
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = Map.of("groups", "SOME_OTHER_GROUP");

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> service.applyScopeRoleMapping(client, claims, Set.of(), userDetailsResponse));
        assertEquals("INVALID_SCOPE", exception.getError().getErrorCode());
    }

    @Test
    void applyScopeRoleMapping_externalPreference_requestedScopeSubsetOfResolved_succeeds() {
        ExternalIdpRegisteredClient client = externalClient(
                rule("VWAG_STORE_PRE_GROUP_DEV", "IgniteStoreSeller,IgniteStorePortfolioManager"));
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = Map.of("groups", "VWAG_STORE_PRE_GROUP_DEV");

        service.applyScopeRoleMapping(client, claims, Set.of("IgniteStoreSeller"), userDetailsResponse);

        assertEquals(Set.of("IgniteStoreSeller", "IgniteStorePortfolioManager"), userDetailsResponse.getScopes());
    }

    @Test
    void applyScopeRoleMapping_externalPreference_requestedScopeNotSubsetOfResolved_throwsInvalidScope() {
        ExternalIdpRegisteredClient client = externalClient(rule("VWAG_STORE_PRE_GROUP_DEV", "IgniteStoreSeller"));
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = Map.of("groups", "VWAG_STORE_PRE_GROUP_DEV");

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> service.applyScopeRoleMapping(client, claims, Set.of("SomeOtherScope"), userDetailsResponse));
        assertEquals("INVALID_SCOPE", exception.getError().getErrorCode());
    }

    @Test
    void applyScopeRoleMapping_externalPreference_noRoleClaimKeyConfigured_usesDefaultGroupsKey() {
        ExternalIdpRegisteredClient client = externalClient(rule("VWAG_STORE_PRE_GROUP_DEV", "IgniteStoreSeller"));
        client.setRoleClaimKey(null);
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = Map.of("groups", "VWAG_STORE_PRE_GROUP_DEV");

        service.applyScopeRoleMapping(client, claims, Set.of(), userDetailsResponse);

        assertEquals(Set.of("IgniteStoreSeller"), userDetailsResponse.getScopes());
    }

    @Test
    void applyScopeRoleMapping_externalPreference_noScopeRoleMappingsConfigured_throwsInvalidScope() {
        ExternalIdpRegisteredClient client = externalClient();
        client.setScopeRoleMappings(List.of());
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> service.applyScopeRoleMapping(client, Map.of(), Set.of(), userDetailsResponse));
        assertEquals("INVALID_SCOPE", exception.getError().getErrorCode());
    }

    @Test
    void applyScopeRoleMapping_externalPreference_customRoleClaimKey_usedInsteadOfDefault() {
        ExternalIdpRegisteredClient client = externalClient(rule("VWAG_STORE_PRE_GROUP_DEV", "IgniteStoreSeller"));
        client.setRoleClaimKey("roles");
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = Map.of("roles", "VWAG_STORE_PRE_GROUP_DEV");

        service.applyScopeRoleMapping(client, claims, Set.of(), userDetailsResponse);

        assertEquals(Set.of("IgniteStoreSeller"), userDetailsResponse.getScopes());
    }

    // ── BOTH preference (10.3) ───────────────────────────────────────────────
    // Note: uidamUserScope is always non-empty by this point (the empty-scope gate above
    // already throws otherwise), so the matched external scope is merged into the
    // (non-empty) internal scope, producing the union of both.

    @Test
    void applyScopeRoleMapping_bothPreference_roleMatches_unionsInternalAndExternalScopes() {
        ExternalIdpRegisteredClient client = bothClient(rule("VWAG_STORE_PRE_GROUP_DEV", "IgniteStoreSeller"));
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = Map.of("groups", "VWAG_STORE_PRE_GROUP_DEV");

        service.applyScopeRoleMapping(client, claims, Set.of(), userDetailsResponse);

        assertEquals(Set.of("SelfManage", "IgniteStoreSeller"), userDetailsResponse.getScopes());
    }

    @Test
    void applyScopeRoleMapping_bothPreference_noRoleMatch_throwsInvalidScope() {
        ExternalIdpRegisteredClient client = bothClient(rule("VWAG_STORE_PRE_GROUP_DEV", "IgniteStoreSeller"));
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = Map.of("groups", "UNMATCHED_GROUP");

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> service.applyScopeRoleMapping(client, claims, Set.of(), userDetailsResponse));
        assertEquals("INVALID_SCOPE", exception.getError().getErrorCode());
    }

    // ── extractRoleValues (via EXTERNAL preference role matching) ──────────
    // Note: role matching requires an *exact* set match between the configured
    // externalRoles and the extracted IDP token roles (see resolveScopeForExternalScopePreference).

    @Test
    void applyScopeRoleMapping_roleClaimAsList_exactSetMatch_resolvesMappedScope() {
        ExternalIdpRegisteredClient client = externalClient(rule("ADMIN,USER", "ManageUsers"));
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = new HashMap<>();
        claims.put("groups", List.of("USER", "ADMIN"));

        service.applyScopeRoleMapping(client, claims, Set.of(), userDetailsResponse);

        assertEquals(Set.of("ManageUsers"), userDetailsResponse.getScopes());
    }

    @Test
    void applyScopeRoleMapping_roleClaimSpaceSeparated_splitsCorrectly() {
        ExternalIdpRegisteredClient client = externalClient(rule("ADMIN,USER", "ManageUsers"));
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = Map.of("groups", "USER ADMIN");

        service.applyScopeRoleMapping(client, claims, Set.of(), userDetailsResponse);

        assertEquals(Set.of("ManageUsers"), userDetailsResponse.getScopes());
    }

    @Test
    void applyScopeRoleMapping_roleClaimAsList_partialOverlapOnly_doesNotMatch() {
        ExternalIdpRegisteredClient client = externalClient(rule("ADMIN", "ManageUsers"));
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = new HashMap<>();
        claims.put("groups", List.of("USER", "ADMIN"));

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> service.applyScopeRoleMapping(client, claims, Set.of(), userDetailsResponse));
        assertEquals("INVALID_SCOPE", exception.getError().getErrorCode());
    }

    @Test
    void applyScopeRoleMapping_roleValueCaseMismatch_doesNotMatch() {
        ExternalIdpRegisteredClient client = externalClient(rule("ADMIN", "ManageUsers"));
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");
        Map<String, Object> claims = Map.of("groups", "admin");

        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> service.applyScopeRoleMapping(client, claims, Set.of(), userDetailsResponse));
        assertEquals("INVALID_SCOPE", exception.getError().getErrorCode());
    }

    // ── OIDC scope exclusion ─────────────────────────────────────────────────

    @Test
    void applyScopeRoleMapping_internalPreference_requestedScopeIncludesOidcScopes_ExcludedFromAppScopeCheck() {
        ExternalIdpRegisteredClient client = internalClient();
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage", "SelfUserManage");

        // openid/profile/email/address/phone are id_token/OIDC scopes, not UIDAM application scopes, and
        // must be excluded before checking against uidamUserScope - only "SelfManage" is checked here.
        service.applyScopeRoleMapping(client, Map.of(),
                Set.of("openid", "profile", "email", "address", "phone", "SelfManage"), userDetailsResponse);

        assertEquals(Set.of("SelfManage", "SelfUserManage"), userDetailsResponse.getScopes());
    }

    @Test
    void applyScopeRoleMapping_internalPreference_requestedScopeOnlyOidcScopes_TreatedAsNoAppScopeRequested() {
        ExternalIdpRegisteredClient client = internalClient();
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage", "SelfUserManage");

        // Only OIDC scopes requested -> after exclusion, the app-scope request is empty, so the full
        // uidamUserScope is granted (mirrors the "no requested scope" behavior).
        service.applyScopeRoleMapping(client, Map.of(), Set.of("openid", "email"), userDetailsResponse);

        assertEquals(Set.of("SelfManage", "SelfUserManage"), userDetailsResponse.getScopes());
    }

    @Test
    void applyScopeRoleMapping_internalPreference_oidcScopesDoNotMaskInvalidAppScope_throwsInvalidScope() {
        ExternalIdpRegisteredClient client = internalClient();
        UserDetailsResponse userDetailsResponse = userWithScopes("SelfManage");

        // OIDC scopes must not mask an app scope that genuinely has no overlap with uidamUserScope.
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> service.applyScopeRoleMapping(client, Map.of(), Set.of("openid", "email", "OtherScope"),
                        userDetailsResponse));
        assertEquals("INVALID_SCOPE", exception.getError().getErrorCode());
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private UserDetailsResponse userWithScopes(String... scopes) {
        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setScopes(new HashSet<>(List.of(scopes)));
        return userDetailsResponse;
    }

    private ScopeRoleMapping rule(String externalRole, String internalScope) {
        ScopeRoleMapping mapping = new ScopeRoleMapping();
        mapping.setExternalRoles(externalRole);
        mapping.setInternalScopes(internalScope);
        return mapping;
    }

    private ExternalIdpRegisteredClient internalClient() {
        ExternalIdpRegisteredClient client = new ExternalIdpRegisteredClient();
        client.setRegistrationId("google");
        client.setScopePreference(ScopePreference.INTERNAL);
        return client;
    }

    private ExternalIdpRegisteredClient externalClient(ScopeRoleMapping... rules) {
        ExternalIdpRegisteredClient client = new ExternalIdpRegisteredClient();
        client.setRegistrationId("google");
        client.setScopePreference(ScopePreference.EXTERNAL);
        client.setScopeRoleMappings(List.of(rules));
        return client;
    }

    private ExternalIdpRegisteredClient bothClient(ScopeRoleMapping... rules) {
        ExternalIdpRegisteredClient client = new ExternalIdpRegisteredClient();
        client.setRegistrationId("google");
        client.setScopePreference(ScopePreference.BOTH);
        client.setScopeRoleMappings(List.of(rules));
        return client;
    }
}
