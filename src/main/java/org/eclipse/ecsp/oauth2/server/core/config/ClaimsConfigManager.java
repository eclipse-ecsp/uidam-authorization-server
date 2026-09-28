/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.config;

import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.audit.context.HttpRequestContext;
import org.eclipse.ecsp.oauth2.server.core.audit.context.TokenAuthenticationContext;
import org.eclipse.ecsp.oauth2.server.core.audit.context.UserActorContext;
import org.eclipse.ecsp.oauth2.server.core.audit.enums.AuditEventType;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ClientProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.IdTokenProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.SignupClientConfig;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UserProperties;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.metrics.MetricType;
import org.eclipse.ecsp.oauth2.server.core.request.dto.FederatedUserDto;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.service.ClaimMappingService;
import org.eclipse.ecsp.oauth2.server.core.service.ScopeRoleClaimMappingService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils;
import org.eclipse.ecsp.oauth2.server.core.utils.OidcTokenHashingUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.AUTHORIZATION_CODE_GRANT_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_ACCOUNT_ID;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_ACCOUNT_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_EXTERNAL_IDP_ID_TOKEN;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_HEADER_ID_TOKEN_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_HEADER_JWT_ACCESS_TOKEN_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_HEADER_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_LAST_LOGON;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_SCOPES;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_TENANT_ID;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_USERNAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_USER_ID;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLIENT_CREDENTIALS_GRANT_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.COMMA_DELIMITER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CREATE_USER_MODE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.FETCH_INTERNAL_USER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.REFRESH_TOKEN_GRANT_TYPE;

/**
 * The ClaimsConfigManager class is a configuration class that manages claims in
 * OAuth2 tokens. It handles both standard OAuth2 token customization and federated
 * authentication scenarios, including:
 * - Custom claim generation for access and ID tokens
 * - Support for multiple authentication grant types
 * - User claim mapping and validation
 * - Automatic user creation for federated users (when configured)
 */
@Configuration
public class ClaimsConfigManager {
    private static final int TENANT_PREFIX_PARTS = 2;
    private static final String COMPONENT_NAME = "UIDAM_AUTHORIZATION_SERVER";

    /**
     * Prefix used in {@code custom-attributes-for-claims} to force lookup of a key in the
     * user's dynamic/custom {@code additionalAttributes} map (from {@code user_attribute_values}),
     * even if the key would otherwise match a mandatory {@link UserDetailsResponse} field name.
     * Keys without this prefix are resolved directly against the mandatory fields instead
     * (see {@link #resolveMandatoryFieldClaim}).
     */
    private static final String CUSTOM_ATTRIBUTE_CLAIM_PREFIX = "ATTR_";

    private static final Logger LOGGER = LoggerFactory.getLogger(ClaimsConfigManager.class);

    private final TenantConfigurationService tenantConfigurationService;
    private final UserManagementClient userManagementClient;
    private final ClaimMappingService claimMappingService;
    private final AuthorizationMetricsService authorizationMetricsService;
    private final AuditLogger auditLogger;
    private final ScopeRoleClaimMappingService scopeRoleClaimMappingService;

    /**
     * Constructor for ClaimsConfigManager. It initializes the tenant configuration service
     * for dynamic tenant resolution.
     *
     * @param tenantConfigurationService the service to retrieve tenant properties from
     * @param claimMappingService the service for claim mapping operations
     * @param userManagementClient the client for user management operations
     * @param authorizationMetricsService the service for authorization metrics
     * @param auditLogger the audit logger
     * @param scopeRoleClaimMappingService the service for dynamic external-role → internal-scope mapping
     */
    public ClaimsConfigManager(TenantConfigurationService tenantConfigurationService,
            ClaimMappingService claimMappingService,
            UserManagementClient userManagementClient,
            AuthorizationMetricsService authorizationMetricsService,
            AuditLogger auditLogger,
            ScopeRoleClaimMappingService scopeRoleClaimMappingService) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.claimMappingService = claimMappingService;
        this.userManagementClient = userManagementClient;
        this.authorizationMetricsService = authorizationMetricsService;
        this.auditLogger = auditLogger;
        this.scopeRoleClaimMappingService = scopeRoleClaimMappingService;
    }

    
    /**
     * This method retrieves the current tenant properties from the TenantConfigurationService. It throws an exception
     * if the service is not initialized or if no tenant properties are found.
     *
     * @return TenantProperties containing the properties of the current tenant.
     * @throws IllegalStateException if TenantConfigurationService is not initialized or no tenant properties are found.
     */
    private TenantProperties getCurrentTenantProperties() {
        if (tenantConfigurationService == null) {
            throw new IllegalStateException("TenantConfigurationService not initialized");
        }
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        if (tenantProperties == null) {
            throw new IllegalStateException("No tenant properties found for current tenant");
        }
        return tenantProperties;
    }

    /**
     * This method retrieves an OAuth2TokenCustomizer implementation to customize
     * the OAuth 2.0 Token attributes contained within the OAuth2TokenContext.
     *
     * @param cacheClientUtils Utility class for cache client operations.
     * @return OAuth2TokenCustomizer for customizing JWT token attributes.
     */
    @Bean
    @Primary
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(CacheClientUtils cacheClientUtils) {
        return context -> {
            JwtClaimsSet.Builder claimsBuilder = context.getClaims();
            Set<String> scopeSet = claimsBuilder.build().getClaim(OAuth2ParameterNames.SCOPE);

            UserDetailsResponse userDetailsResponse = retrieveUserDetails(context, scopeSet);

            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                LOGGER.debug("jwtTokenCustomizer: building ACCESS_TOKEN claims for grantType={}, clientId={}",
                        context.getAuthorizationGrantType().getValue(), context.getRegisteredClient().getClientId());
                processAccessToken(context, cacheClientUtils, userDetailsResponse, claimsBuilder, scopeSet);
            } else if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                LOGGER.debug("jwtTokenCustomizer: building ID_TOKEN claims for grantType={}, clientId={}",
                        context.getAuthorizationGrantType().getValue(), context.getRegisteredClient().getClientId());
                addClaimsForIdToken(context, userDetailsResponse, claimsBuilder);
            } else {
                LOGGER.debug("jwtTokenCustomizer: unhandled token type '{}' - no claims added",
                        context.getTokenType().getValue());
            }
        };
    }

    /**
     * Retrieves user details based on the authentication context.
     * Supports both internal password authentication and federated authentication.
     *
     * @param context The JWT encoding context
     * @param requestedScope the Requested Scope (client's requested {@code scope} claim); used to
     *         drive dynamic scope-role mapping (Rule 2) for federated logins
     * @return UserDetailsResponse or null if not applicable
     */
    private UserDetailsResponse retrieveUserDetails(JwtEncodingContext context, Set<String> requestedScope) {
        String grantType = context.getAuthorizationGrantType().getValue();
        
        if (!AUTHORIZATION_CODE_GRANT_TYPE.equals(grantType) 
                && !REFRESH_TOKEN_GRANT_TYPE.equals(grantType)) {
            return null;
        }
        
        if (context.getPrincipal() instanceof CustomUserPwdAuthenticationToken customUserPwdAuthenticationToken) {
            LOGGER.debug("Non Federated user authentication");
            authorizationMetricsService.incrementMetricsForTenant(
                    getCurrentTenantProperties().getTenantId(),
                    MetricType.SUCCESS_LOGIN_BY_INTERNAL_CREDENTIALS);
            return userManagementClient.getUserDetailsByUsername(
                    customUserPwdAuthenticationToken.getName(),
                    customUserPwdAuthenticationToken.getAccountName());
        }
        
        if (context.getPrincipal() instanceof OAuth2AuthenticationToken oauth2AuthenticationToken) {
            LOGGER.debug("Federated user authentication");
            return getUserDetailsForFederatedUser(oauth2AuthenticationToken, requestedScope);
        }
        
        return null;
    }

    /**
     * Processes access token by adding claims and logging audit events.
     *
     * @param context The JWT encoding context
     * @param cacheClientUtils The cache client utilities
     * @param userDetailsResponse The user details
     * @param claimsBuilder The JWT claims builder
     * @param scopeSet The set of scopes
     */
    private void processAccessToken(JwtEncodingContext context, CacheClientUtils cacheClientUtils,
                                    UserDetailsResponse userDetailsResponse, 
                                    JwtClaimsSet.Builder claimsBuilder, Set<String> scopeSet) {
        ClientCacheDetails clientDetails = cacheClientUtils.getClientDetails(
                context.getRegisteredClient().getClientId());
        addClaimsForAccessToken(context, clientDetails, userDetailsResponse, claimsBuilder, scopeSet);
        
        String grantType = context.getAuthorizationGrantType().getValue();
        
        if (REFRESH_TOKEN_GRANT_TYPE.equals(grantType)) {
            logTokenRefreshed(context, userDetailsResponse, clientDetails);
        } else {
            logAccessTokenGenerated(context, userDetailsResponse, clientDetails, grantType);
        }
    }

    /**
     * This method retrieves user details for a federated user. A federated user is
     * a user who has authenticated using an external identity provider (IdP) via
     * OAuth2.
     *
     * @param oauth2AuthenticationToken OAuth2AuthenticationToken representing the
     *                                  authenticated federated user.
     * @param requestedScope the Requested Scope (client's requested {@code scope} claim); used to
     *         drive dynamic scope-role mapping (Rule 2)
     * @return UserDetailsResponse containing the details of the federated user.
     */
    private UserDetailsResponse getUserDetailsForFederatedUser(OAuth2AuthenticationToken oauth2AuthenticationToken,
            Set<String> requestedScope) {
        String tenantPrefixedRegistrationId = oauth2AuthenticationToken.getAuthorizedClientRegistrationId();
        String tenantId = getCurrentTenantProperties().getTenantId();
        authorizationMetricsService.incrementMetricsForTenant(
                                                            tenantId,
                                                            MetricType.TOTAL_LOGIN_ATTEMPTS);
        
        // Find external IDP client with tenant validation and registration ID extraction
        ExternalIdpRegisteredClient idpClient = findExternalIdpClient(tenantPrefixedRegistrationId);
        
        if (idpClient == null) {
            throw new OAuth2AuthenticationException(
                new OAuth2Error(
                    "invalid_idp_configuration",
                    "No external IDP configuration found for: " + tenantPrefixedRegistrationId,
                    null
                )
            );
        }

        String mode = idpClient.getTokenInfoSource();
        if (!FETCH_INTERNAL_USER.equalsIgnoreCase(mode)) {
            return null; // Early return if not fetching internal user
        }

        Map<String, Object> claims = oauth2AuthenticationToken.getPrincipal().getAttributes();
        String userName = String.valueOf(claims.get(idpClient.getUserNameAttributeName()));
        
        // Extract original registration ID for the method call
        String originalRegistrationId = idpClient.getRegistrationId();
        
        // Use StringBuilder for better performance when constructing federated username
        int expectedLength = originalRegistrationId.length() + userName.length() + 1;
        StringBuilder federatedUserNameBuilder = new StringBuilder(expectedLength);
        String federatedUserName = federatedUserNameBuilder
                .append(originalRegistrationId)
                .append("_")
                .append(userName)
                .toString();
        
        UserDetailsResponse userDetailsResponse = getFederatedUserDetails(originalRegistrationId,
                                                                        federatedUserName,
                                                                        idpClient,
                                                                        claims);

        // Apply dynamic external-role -> internal-scope mapping on every federated login
        LOGGER.debug("Federated claims received: registrationId={}, claimCount={}",
                tenantPrefixedRegistrationId, claims.size());
        try {
            scopeRoleClaimMappingService.applyScopeRoleMapping(
                    idpClient, claims, requestedScope, userDetailsResponse);
            recordScopeRoleMappingOutcome(
                    tenantId, idpClient.getRegistrationId(), userDetailsResponse, null);
        } catch (RuntimeException ex) {
            recordScopeRoleMappingOutcome(
                    tenantId, idpClient.getRegistrationId(), userDetailsResponse, ex);
            throw ex;
        }

        // Log successful external IDP authentication
        logIdpAuthenticationSuccess(userDetailsResponse, oauth2AuthenticationToken);
        
        authorizationMetricsService.incrementMetricsForTenantAndIdp(
                                                                tenantId,
                                                                idpClient.getRegistrationId(),
                                                                MetricType.SUCCESS_LOGIN_BY_EXTERNAL_IDP_CREDENTIALS);
        authorizationMetricsService.incrementMetricsForTenant(
                                                                tenantId,
                                                                MetricType.SUCCESS_LOGIN_ATTEMPTS);
        return userDetailsResponse;
    }

    /**
     * Finds the external Identity Provider (IdP) client configuration based on the tenant-prefixed registration ID.
     * This method handles tenant validation and extracts the original registration ID from the tenant-prefixed format.
     * It ensures that only users from the current tenant can access their corresponding IDP configurations. The
     * registration ID must be in the format: "tenant-provider" (e.g., "demo-google", "ecsp-azure")
     *
     * @param tenantPrefixedRegistrationId The tenant-prefixed registration ID (e.g., "demo-google")
     * @return ExternalIdpRegisteredClient The matching IdP client configuration, or null if not found
     * @throws OAuth2AuthenticationException if the tenant prefix doesn't match current tenant or registration ID is
     *     invalid.
     */
    private ExternalIdpRegisteredClient findExternalIdpClient(String tenantPrefixedRegistrationId) {
        if (tenantPrefixedRegistrationId == null) {
            throw new OAuth2AuthenticationException(
                new OAuth2Error(
                    "invalid_registration_id",
                    "Registration ID cannot be null",
                    null
                )
            );
        }

        // Get current tenant properties - single call optimized
        TenantProperties tenantProperties = getCurrentTenantProperties();
        String currentTenantId = tenantProperties.getTenantId();
        
        // Registration ID must be in tenant-prefixed format: "tenant-provider"
        if (!tenantPrefixedRegistrationId.contains("-")) {
            throwInvalidRegistrationFormatException(tenantPrefixedRegistrationId);
        }
        
        String[] parts = tenantPrefixedRegistrationId.split("-", TENANT_PREFIX_PARTS);
        if (parts.length != TENANT_PREFIX_PARTS || parts[0].isEmpty() || parts[1].isEmpty()) {
            throwInvalidRegistrationFormatException(tenantPrefixedRegistrationId);
        }

        String tenantPrefix = parts[0];
        String originalRegistrationId = parts[1];
        
        // Validate that the tenant prefix matches the current tenant
        if (!currentTenantId.equals(tenantPrefix)) {
            throwInvalidTenantAccessException(tenantPrefix, currentTenantId);
        }
        
        LOGGER.debug("Validated tenant prefix '{}' matches current tenant, extracted registration ID: '{}'", 
            tenantPrefix, originalRegistrationId);
        
        // Find the IDP client configuration using the original registration ID
        return tenantProperties.getExternalIdpRegisteredClientList().stream()
                .filter(x -> x.getRegistrationId().equalsIgnoreCase(originalRegistrationId))
                .findFirst()
                .orElse(null);
    }

    /**
     * Helper method to throw a consistent invalid tenant access exception.
     *
     * @param tenantPrefix The tenant prefix from the registration ID
     * @param currentTenantId The current tenant ID
     * @throws OAuth2AuthenticationException Always throws this exception with consistent error message
     */
    private void throwInvalidTenantAccessException(String tenantPrefix, String currentTenantId) {
        StringBuilder errorMessage = new StringBuilder("Access denied: Registration ID belongs to tenant '")
                .append(tenantPrefix)
                .append("' but current tenant is '")
                .append(currentTenantId)
                .append("'");
        
        throw new OAuth2AuthenticationException(
                new OAuth2Error("invalid_tenant_access", errorMessage.toString(), null));
    }
    
    /**
     * Helper method to throw a consistent invalid registration format exception.
     *
     * @param registrationId The invalid registration ID
     * @throws OAuth2AuthenticationException Always throws this exception with consistent error message
     */
    private void throwInvalidRegistrationFormatException(String registrationId) {
        StringBuilder errorMessage = new StringBuilder("Registration ID must be in format 'tenant-provider' but was: ")
                .append(registrationId);
        
        throw new OAuth2AuthenticationException(
            new OAuth2Error(
                "invalid_registration_format",
                errorMessage.toString(),
                null
            )
        );
    }

    /**
     * Retrieves or creates user details for a federated user. This method first attempts to find
     * an existing user with the federated username. If the user is not found and user creation
     * is enabled, it will create a new user based on the IdP claims.
     *
     * @param idpRegisteredClientId The registration ID of the external IdP client
     * @param federatedUserName The constructed federated username (typically idpId_username)
     * @param idpClient The external IdP client configuration
     * @param claims The claims/attributes received from the external IdP
     * @return UserDetailsResponse containing the user's details
     * @throws OAuth2AuthenticationException if user creation is not allowed or claim validation fails
     * @throws RuntimeException if the IdP configuration is invalid or user creation fails
     */
    private UserDetailsResponse getFederatedUserDetails(String idpRegisteredClientId, String federatedUserName, 
            ExternalIdpRegisteredClient idpClient, Map<String, Object> claims) {
        try {
            return userManagementClient.getUserDetailsByUsername(federatedUserName, null);
        } catch (OAuth2AuthenticationException e) {
            if (!CustomOauth2TokenGenErrorCodes.USER_NOT_FOUND.name().equals(e.getError().getErrorCode())) {
                throw e;
            }
            return handleUserNotFound(idpRegisteredClientId, idpClient, claims);
        }
    }

    /**
     * Handles the scenario when a federated user is not found in the system.
     * This method implements the user creation logic for federated authentication:
     * 1. Verifies if user creation is allowed for the IdP
     * 2. Validates the claims from the IdP against configured conditions
     * 3. Maps the IdP claims to internal user attributes
     * 4. Creates a new user in the system
     *
     * @param idpRegisteredClientId The registration ID of the external IdP client
     * @param idpClient The configuration details for the external IdP
     * @param claims The claims/attributes received from the external IdP
     * @return UserDetailsResponse The newly created user's details
     * @throws RuntimeException if user creation is not allowed or if claim validation fails
     */
    private UserDetailsResponse handleUserNotFound(String idpRegisteredClientId, 
            ExternalIdpRegisteredClient idpClient, Map<String, Object> claims) {
        if (!CREATE_USER_MODE.equalsIgnoreCase(idpClient.getCreateUserMode())) {
            throw new OAuth2AuthenticationException(
                new OAuth2Error(
                    "user_creation_not_allowed",
                    "User creation not allowed for: " + idpRegisteredClientId,
                    null
                )
            );
        }
        if (!claimMappingService.validateClaimCondition(idpRegisteredClientId, claims)) {
            throw new OAuth2AuthenticationException(
                new OAuth2Error(
                    "invalid_claim_validation",
                    "Claim validation failed for registrationId: " + idpRegisteredClientId,
                    null
                )
            );
        }
        FederatedUserDto userRequest = claimMappingService.mapClaimsToUserRequest(
                idpRegisteredClientId, claims, idpClient.getUserNameAttributeName());
        return userManagementClient.createFedratedUser(userRequest);
    }

    /**
     * This method adds claims to the access token. Claims are additional
     * information about the user or client that are included in the access token.
     * The claims are customized based on the context, registered client details,
     * and user details response.
     *
     * @param context                 JwtEncodingContext containing the OAuth 2.0
     *                                JWT Token attributes.
     * @param registeredClientDetails RegisteredClientDetails containing the details
     *                                of the registered client.
     * @param userDetailsResponse     UserDetailsResponse containing the details of
     *                                the user.
     * @param claimsBuilder           JwtClaimsSet.Builder used to build the JWT
     *                                claims set.
     * @param scopeSet                Set of scopes associated with the token.
     */
    private void addClaimsForAccessToken(JwtEncodingContext context, ClientCacheDetails clientDetails,
            UserDetailsResponse userDetailsResponse, JwtClaimsSet.Builder claimsBuilder, Set<String> scopeSet) {
        context.getJwsHeader().header(CLAIM_HEADER_TYPE, CLAIM_HEADER_JWT_ACCESS_TOKEN_TYPE);
        setStandardClaims(claimsBuilder);
        String clientId = (clientDetails != null && clientDetails.getRegisteredClient() != null)
                ? clientDetails.getRegisteredClient().getClientId() : null;
        boolean isFederatedUser = isFederatedUser(context.getPrincipal());
        if (AUTHORIZATION_CODE_GRANT_TYPE.equals(context.getAuthorizationGrantType().getValue())) {
            setUserCustomClaims(claimsBuilder, userDetailsResponse, clientId);
            scopeSet = populateUserScopes(userDetailsResponse, scopeSet, isFederatedUser);
            addScopeAndScopes(clientDetails, userDetailsResponse, claimsBuilder, scopeSet, false,
                    isFederatedUser);
            LOGGER.debug("Claims added to JWT Access token for grant type - authorization_code");
        } else if (CLIENT_CREDENTIALS_GRANT_TYPE.equals(context.getAuthorizationGrantType().getValue())) {
            setClientCustomClaims(clientDetails, claimsBuilder);
            addScopeAndScopes(clientDetails, null, claimsBuilder, scopeSet, true, isFederatedUser);
            LOGGER.debug("Claims added to JWT Access token for grant type - client_credentials");
        } else if (REFRESH_TOKEN_GRANT_TYPE.equals(context.getAuthorizationGrantType().getValue())) {
            if (userDetailsResponse != null) {
                setUserCustomClaims(claimsBuilder, userDetailsResponse, clientId);
                scopeSet = populateUserScopes(userDetailsResponse, scopeSet, isFederatedUser);
            } else {
                LOGGER.warn("userDetailsResponse is null during refresh_token grant "
                        + "(PKCE/public client flow) - skipping user claims, using existing scope");
            }
            addScopeAndScopes(clientDetails, null, claimsBuilder, scopeSet, false, isFederatedUser);
            LOGGER.debug("Claims added to JWT Access token for grant type - refresh_token");
        }
    }

    /**
     * This method adds claims to the ID token. Claims are additional information
     * about the user that are included in the ID token. The claims are customized
     * based on the context and user details response.
     *
     * <p>Additional claims are selected by {@link IdTokenProperties} and resolved only from the UIDAM
     * {@link UserDetailsResponse}. Standard ID-token claims cannot be overwritten through configuration.
     *
     * @param context             JwtEncodingContext containing the OAuth 2.0 JWT
     *                            Token attributes.
     * @param userDetailsResponse UserDetailsResponse containing the details of the
     *                            user. May be {@code null} when the federated IdP is configured
     *                            with a {@code token-info-source} other than
     *                            {@code FETCH_INTERNAL_USER}; user-derived claims are skipped in
     *                            that case.
     */
    private void addClaimsForIdToken(JwtEncodingContext context, UserDetailsResponse userDetailsResponse,
            JwtClaimsSet.Builder claimsBuilder) {

        context.getJwsHeader().header(CLAIM_HEADER_TYPE, CLAIM_HEADER_ID_TOKEN_TYPE);

        claimsBuilder.claim(JwtClaimNames.JTI, UUID.randomUUID().toString());
        if (userDetailsResponse == null) {
            LOGGER.warn("userDetailsResponse is null while building ID token - skipping user-derived claims");
        } else {
            addUidamSubjectForFederatedUser(context, claimsBuilder, userDetailsResponse);
            addConfiguredClaimsForIdToken(claimsBuilder, userDetailsResponse);
            addOidcScopeClaims(context, claimsBuilder, userDetailsResponse);
        }
        addProtocolTokenHashClaims(context, claimsBuilder);
        addExternalIdpIdToken(context, claimsBuilder);

        LOGGER.debug("Claims added to ID token");
    }

    /**
     * Uses the UIDAM user identifier as the ID-token subject for federated users.
     * Spring Authorization Server initially derives {@code sub} from the external
     * IdP principal, so it must be replaced after the federated user is resolved
     * in UIDAM. Internal users retain the subject established by the authorization
     * server.
     *
     * @param context ID-token encoding context
     * @param claimsBuilder ID-token claims builder
     * @param userDetailsResponse resolved UIDAM user details
     */
    private void addUidamSubjectForFederatedUser(JwtEncodingContext context,
            JwtClaimsSet.Builder claimsBuilder, UserDetailsResponse userDetailsResponse) {
        if (!(context.getPrincipal() instanceof OAuth2AuthenticationToken)) {
            return;
        }
        if (!StringUtils.hasText(userDetailsResponse.getId())) {
            LOGGER.warn("UIDAM user ID is unavailable while building a federated ID token; retaining existing sub");
            return;
        }
        claimsBuilder.subject(userDetailsResponse.getId());
    }

    /**
     * Adds standard OpenID Connect claims selected by the authorized {@code profile},
     * {@code email}, {@code address}, and {@code phone} scopes. UIDAM field names are
     * translated to their standard OIDC claim names.
     *
     * @param context ID-token encoding context
     * @param claimsBuilder ID-token claims builder
     * @param userDetailsResponse UIDAM user details
     */
    private void addOidcScopeClaims(JwtEncodingContext context, JwtClaimsSet.Builder claimsBuilder,
            UserDetailsResponse userDetailsResponse) {
        Set<String> authorizedScopes = context.getAuthorizedScopes();
        if (CollectionUtils.isEmpty(authorizedScopes)) {
            return;
        }

        if (authorizedScopes.contains(OidcScopes.PROFILE)) {
            addProfileScopeClaims(claimsBuilder, userDetailsResponse);
        }
        if (authorizedScopes.contains(OidcScopes.EMAIL)) {
            addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.EMAIL, "email");
            addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.EMAIL_VERIFIED,
                    "email_verified", "emailVerified");
        }
        if (authorizedScopes.contains(OidcScopes.ADDRESS)) {
            Object address = resolveAddressClaim(userDetailsResponse);
            if (!ObjectUtils.isEmpty(address)) {
                claimsBuilder.claim(StandardClaimNames.ADDRESS, address);
            }
        }
        if (authorizedScopes.contains(OidcScopes.PHONE)) {
            addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.PHONE_NUMBER,
                    "phone_number", "phoneNumber");
            addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.PHONE_NUMBER_VERIFIED,
                    "phone_number_verified", "phoneNumberVerified");
        }
    }

    private void addProfileScopeClaims(JwtClaimsSet.Builder claimsBuilder,
            UserDetailsResponse userDetailsResponse) {
        Object name = resolveUserDetailValue(userDetailsResponse, "name", "fullName");
        if (ObjectUtils.isEmpty(name)) {
            name = buildFullName(userDetailsResponse);
        }
        if (!ObjectUtils.isEmpty(name)) {
            claimsBuilder.claim(StandardClaimNames.NAME, name);
        }
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.GIVEN_NAME,
                "given_name", "givenName", "firstName");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.FAMILY_NAME,
                "family_name", "familyName", "lastName");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.MIDDLE_NAME,
                "middle_name", "middleName");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.NICKNAME,
                "nickname", "nickName");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.PREFERRED_USERNAME,
                "preferred_username", "preferredUsername", "userName");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.PROFILE, "profile");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.PICTURE, "picture");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.WEBSITE, "website");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.GENDER, "gender");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.BIRTHDATE,
                "birthdate", "birthDate");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.ZONEINFO,
                "zoneinfo", "timeZone", "timezone");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.LOCALE, "locale");
        addClaimIfPresent(claimsBuilder, userDetailsResponse, StandardClaimNames.UPDATED_AT,
                "updated_at", "updatedAt");
    }

    private void addClaimIfPresent(JwtClaimsSet.Builder claimsBuilder, UserDetailsResponse userDetailsResponse,
            String claimName, String... sourceKeys) {
        Object value = resolveUserDetailValue(userDetailsResponse, sourceKeys);
        if (!ObjectUtils.isEmpty(value)) {
            claimsBuilder.claim(claimName, value);
        }
    }

    private Object resolveUserDetailValue(UserDetailsResponse userDetailsResponse, String... sourceKeys) {
        Map<String, Object> additionalAttributes = userDetailsResponse.getAdditionalAttributes();
        for (String sourceKey : sourceKeys) {
            Object value = resolveMandatoryFieldClaim(userDetailsResponse, sourceKey);
            if (ObjectUtils.isEmpty(value) && !CollectionUtils.isEmpty(additionalAttributes)) {
                value = additionalAttributes.get(sourceKey);
            }
            if (!ObjectUtils.isEmpty(value)) {
                return value;
            }
        }
        return null;
    }

    private Object buildFullName(UserDetailsResponse userDetailsResponse) {
        Object givenName = resolveUserDetailValue(userDetailsResponse, "given_name", "givenName", "firstName");
        Object familyName = resolveUserDetailValue(userDetailsResponse, "family_name", "familyName", "lastName");
        String fullName = ((ObjectUtils.isEmpty(givenName) ? "" : givenName.toString()) + " "
                + (ObjectUtils.isEmpty(familyName) ? "" : familyName.toString())).trim();
        return StringUtils.hasText(fullName) ? fullName : null;
    }

    private Object resolveAddressClaim(UserDetailsResponse userDetailsResponse) {
        Object existingAddress = resolveUserDetailValue(userDetailsResponse, StandardClaimNames.ADDRESS);
        if (existingAddress instanceof Map<?, ?> && !ObjectUtils.isEmpty(existingAddress)) {
            return existingAddress;
        }

        Map<String, Object> address = new LinkedHashMap<>();
        Object formattedAddress = resolveUserDetailValue(userDetailsResponse, "formatted");
        if (ObjectUtils.isEmpty(formattedAddress) && existingAddress instanceof String) {
            formattedAddress = existingAddress;
        }
        putIfPresent(address, "formatted", formattedAddress);

        Object streetAddress = resolveUserDetailValue(userDetailsResponse, "street_address", "streetAddress");
        if (ObjectUtils.isEmpty(streetAddress)) {
            streetAddress = buildStreetAddress(userDetailsResponse);
        }
        putIfPresent(address, "street_address", streetAddress);
        putIfPresent(address, "locality", resolveUserDetailValue(userDetailsResponse, "locality", "city"));
        putIfPresent(address, "region", resolveUserDetailValue(userDetailsResponse, "region", "state"));
        putIfPresent(address, "postal_code",
                resolveUserDetailValue(userDetailsResponse, "postal_code", "postalCode"));
        putIfPresent(address, "country", resolveUserDetailValue(userDetailsResponse, "country"));
        return address.isEmpty() ? null : address;
    }

    private Object buildStreetAddress(UserDetailsResponse userDetailsResponse) {
        Object address1 = resolveUserDetailValue(userDetailsResponse, "address1");
        Object address2 = resolveUserDetailValue(userDetailsResponse, "address2");
        String streetAddress = ((ObjectUtils.isEmpty(address1) ? "" : address1.toString()) + "\n"
                + (ObjectUtils.isEmpty(address2) ? "" : address2.toString())).trim();
        return StringUtils.hasText(streetAddress) ? streetAddress : null;
    }

    private void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (!ObjectUtils.isEmpty(value)) {
            target.put(key, value);
        }
    }

    /**
     * Adds the OpenID Connect hashes for the access token and authorization code used
     * in the initial authorization-code exchange. These values are derived from the
     * protocol artifacts and must never be sourced from configured user attributes.
     *
     * @param context ID-token encoding context
     * @param claimsBuilder ID-token claims builder
     */
    private void addProtocolTokenHashClaims(JwtEncodingContext context, JwtClaimsSet.Builder claimsBuilder) {
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())) {
            return;
        }

        OAuth2Authorization authorization = context.getAuthorization();
        if (authorization == null) {
            LOGGER.warn("Authorization is unavailable while building ID-token hash claims");
            return;
        }

        JwsAlgorithm signingAlgorithm = context.getJwsHeader().build().getAlgorithm();
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
        if (accessToken != null && StringUtils.hasText(accessToken.getToken().getTokenValue())) {
            claimsBuilder.claim(IdTokenClaimNames.AT_HASH,
                    OidcTokenHashingUtil.createTokenHash(accessToken.getToken().getTokenValue(), signingAlgorithm));
        }

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null && StringUtils.hasText(authorizationCode.getToken().getTokenValue())) {
            claimsBuilder.claim(IdTokenClaimNames.C_HASH,
                    OidcTokenHashingUtil.createTokenHash(
                            authorizationCode.getToken().getTokenValue(), signingAlgorithm));
        }
    }

    /**
     * Adds configured claims from UIDAM mandatory fields or dynamic additional attributes.
     * Missing values and standard ID-token claim names are skipped.
     *
     * @param claimsBuilder ID-token claims builder
     * @param userDetailsResponse UIDAM user details
     */
    private void addConfiguredClaimsForIdToken(JwtClaimsSet.Builder claimsBuilder,
            UserDetailsResponse userDetailsResponse) {
        ClientProperties clientProperties = getCurrentTenantProperties().getClient();
        if (clientProperties == null) {
            return;
        }
        IdTokenProperties idTokenProperties = clientProperties.getIdTokenProperties();
        if (idTokenProperties == null) {
            return;
        }
        List<String> configuredClaims = idTokenProperties.getAdditionalClaimNames();
        if (CollectionUtils.isEmpty(configuredClaims)) {
            return;
        }
        Map<String, Object> additionalAttributes = userDetailsResponse.getAdditionalAttributes();
        for (String claimName : configuredClaims) {
            if (idTokenProperties.isMandatoryClaim(claimName)) {
                LOGGER.warn("Ignoring configured standard ID-token claim '{}'", claimName);
                continue;
            }
            Object claimValue = resolveMandatoryFieldClaim(userDetailsResponse, claimName);
            if (ObjectUtils.isEmpty(claimValue) && !CollectionUtils.isEmpty(additionalAttributes)) {
                claimValue = additionalAttributes.get(claimName);
            }
            if (ObjectUtils.isEmpty(claimValue)) {
                LOGGER.warn("Configured ID-token claim '{}' was not found in UIDAM user details", claimName);
                continue;
            }
            claimsBuilder.claim(claimName, claimValue);
        }
    }

    /**
     * Adds the external provider's raw ID token to the UIDAM ID token when enabled
     * for the authenticated provider.
     *
     * <p>If the provider uses OAuth 2.0 without OIDC, no upstream ID token exists
     * and the claim is safely omitted.
     *
     * @param context JWT encoding context containing the federated principal
     * @param claimsBuilder UIDAM ID-token claims builder
     */
    private void addExternalIdpIdToken(JwtEncodingContext context, JwtClaimsSet.Builder claimsBuilder) {
        if (!(context.getPrincipal() instanceof OAuth2AuthenticationToken oauth2Token)) {
            return;
        }

        ExternalIdpRegisteredClient idpClient =
                findExternalIdpClient(oauth2Token.getAuthorizedClientRegistrationId());
        if (idpClient == null || !idpClient.isIncludeIdpIdToken()) {
            return;
        }

        if (!(oauth2Token.getPrincipal() instanceof OidcUser oidcUser)
                || oidcUser.getIdToken() == null
                || !StringUtils.hasText(oidcUser.getIdToken().getTokenValue())) {
            LOGGER.warn("External IdP '{}' is configured to include its ID token, but no OIDC ID token is available",
                    idpClient.getRegistrationId());
            return;
        }

        claimsBuilder.claim(CLAIM_EXTERNAL_IDP_ID_TOKEN, oidcUser.getIdToken().getTokenValue());
        LOGGER.debug("Added external IdP ID token for provider '{}'", idpClient.getRegistrationId());
    }

    /**
     * This method sets custom claims for the client. Claims are additional
     * information about the client that are included in the access token. The
     * claims are customized based on the registered client details.
     *
     * @param clientDetails RegisteredClientDetails containing the details of the registered client.
     *
     * @param claimsBuilder JwtClaimsSet.Builder used to build the JWT claims set.
     */
    private void setClientCustomClaims(ClientCacheDetails clientDetails, JwtClaimsSet.Builder claimsBuilder) {
        LOGGER.info("## setClientCustomClaims - END");
        if (StringUtils.hasText(clientDetails.getAccountType())) {
            claimsBuilder
                    .claim(CLAIM_ACCOUNT_TYPE, clientDetails.getAccountType());
        }
        if (StringUtils.hasText(clientDetails.getAccountName())) {
            claimsBuilder
                    .claim(CLAIM_ACCOUNT_NAME, clientDetails.getAccountName());
        }
        if (StringUtils.hasText(clientDetails.getAccountId())) {
            claimsBuilder
                    .claim(CLAIM_ACCOUNT_ID, clientDetails.getAccountId());
        }
        LOGGER.debug("## setClientCustomClaims - END");
    }

    /**
     * This method sets custom claims for the user. Claims are additional
     * information about the user that are included in the access token. The claims
     * are customized based on the user details response.
     *
     * @param claimsBuilder       JwtClaimsSet.Builder used to build the JWT claims
     *                            set.
     * @param userDetailsResponse UserDetailsResponse containing the details of the
     *                            user.
     */
    private void setUserCustomClaims(JwtClaimsSet.Builder claimsBuilder, UserDetailsResponse userDetailsResponse,
            String clientId) {
        LOGGER.debug("## setUserCustomClaims - START");
        claimsBuilder.claim(CLAIM_USER_ID, userDetailsResponse.getId());
        if (StringUtils.hasText(userDetailsResponse.getLastSuccessfulLoginTime())) {
            claimsBuilder.claim(CLAIM_LAST_LOGON, userDetailsResponse.getLastSuccessfulLoginTime());
        }
        if (StringUtils.hasText(userDetailsResponse.getAccountId())) {
            claimsBuilder.claim(CLAIM_ACCOUNT_ID, userDetailsResponse.getAccountId());
        }
        if (StringUtils.hasText(userDetailsResponse.getUserName())) {
            claimsBuilder.claim(CLAIM_USERNAME, userDetailsResponse.getUserName());
        }
        Map<String, Object> additionalAttributes = userDetailsResponse.getAdditionalAttributes();
        TenantProperties tenantProperties = getCurrentTenantProperties();
        if (!CollectionUtils.isEmpty(additionalAttributes)) {
            LOGGER.info("Adding claims from additional attributes");
            addTenantLevelAdditionalClaims(claimsBuilder, additionalAttributes, tenantProperties);
        }
        // Client-specific claims may reference mandatory fields too, so this must run
        // even when additionalAttributes is empty (unlike the tenant-level claims above).
        addClientSpecificClaims(claimsBuilder, userDetailsResponse, tenantProperties, clientId);
        LOGGER.debug("## setUserCustomClaims - END");
    }

    /**
     * Adds tenant-level additional claim attributes to the JWT based on the
     * {@code tenant.props.*.user.jwt-additional-claim-attributes} allow-list.
     *
     * @param claimsBuilder        the JWT claims builder
     * @param additionalAttributes the user's additional attributes map
     * @param tenantProperties     the current tenant properties
     */
    private void addTenantLevelAdditionalClaims(JwtClaimsSet.Builder claimsBuilder,
            Map<String, Object> additionalAttributes, TenantProperties tenantProperties) {
        UserProperties userProps = tenantProperties.getUser();
        if (userProps == null || !StringUtils.hasText(userProps.getJwtAdditionalClaimAttributes())) {
            return;
        }
        List<String> allowList = Arrays.asList(
                userProps.getJwtAdditionalClaimAttributes().replaceAll("\\s", "").split(COMMA_DELIMITER));
        for (Map.Entry<String, Object> entry : additionalAttributes.entrySet()) {
            if (allowList.contains(entry.getKey())) {
                claimsBuilder.claim(entry.getKey(), entry.getValue());
                LOGGER.debug("Added tenant-level additional claim: {}", entry.getKey());
            }
        }
    }

    /**
     * Adds client-specific additional claim attributes to the JWT based on the matching
     * {@code signup-config-list} entry's {@code custom-attributes-for-claims} property.
     * If the property is absent or blank, no per-client custom claims are added.
     *
     * @param claimsBuilder        the JWT claims builder
     * @param userDetailsResponse  the user's details (source of both mandatory fields and
     *                             the dynamic {@code additionalAttributes} map)
     * @param tenantProperties     the current tenant properties
     * @param clientId             the OAuth2 client ID of the current request (may be null)
     */
    private void addClientSpecificClaims(JwtClaimsSet.Builder claimsBuilder,
            UserDetailsResponse userDetailsResponse, TenantProperties tenantProperties, String clientId) {
        if (!StringUtils.hasText(clientId)) {
            return;
        }
        SignupClientConfig config = tenantProperties.getSignupClientConfig(clientId);
        if (config != null) {
            applyClientConfig(claimsBuilder, userDetailsResponse, config, clientId);
        }
    }

    /**
     * Applies a resolved {@link SignupClientConfig} to write client-specific claims.
     * Uses the explicit {@code custom-attributes-for-claims} allow-list: if blank or
     * null, no custom attributes are added. Each listed key is resolved one of two ways:
     * <ul>
     *   <li>Prefixed with {@value #CUSTOM_ATTRIBUTE_CLAIM_PREFIX} — looked up (after stripping
     *       the prefix) in the user's dynamic {@code additionalAttributes} map, i.e. a custom
     *       signup attribute from {@code user_attribute_values}.</li>
     *   <li>No prefix — resolved directly from the mandatory, fixed {@link UserDetailsResponse}
     *       fields (e.g. {@code userName}, {@code email}) via {@link #resolveMandatoryFieldClaim}.</li>
     * </ul>
     * Missing or empty values are logged and skipped rather than failing the token issuance.
     *
     * @param claimsBuilder       the JWT claims builder
     * @param userDetailsResponse the user's details
     * @param config              the matched signup client config entry
     * @param clientId            the OAuth2 client ID (used for logging)
     */
    private void applyClientConfig(JwtClaimsSet.Builder claimsBuilder,
            UserDetailsResponse userDetailsResponse,
            SignupClientConfig config,
            String clientId) {
        if (!StringUtils.hasText(config.getCustomAttributesForClaims())) {
            LOGGER.debug("Client '{}': customAttributesForClaims not configured, skipping custom claims",
                    clientId);
            return;
        }
        Map<String, Object> additionalAttributes = userDetailsResponse.getAdditionalAttributes();
        List<String> claimKeys = Arrays.stream(config.getCustomAttributesForClaims().split(COMMA_DELIMITER))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
        for (String key : claimKeys) {
            try {
                boolean isCustomAttribute = key.startsWith(CUSTOM_ATTRIBUTE_CLAIM_PREFIX);
                String resolvedKey = isCustomAttribute
                        ? key.substring(CUSTOM_ATTRIBUTE_CLAIM_PREFIX.length())
                        : key;
                Object value = isCustomAttribute
                        ? resolveCustomAttributeClaim(additionalAttributes, resolvedKey)
                        : resolveMandatoryFieldClaim(userDetailsResponse, resolvedKey);
                if (ObjectUtils.isEmpty(value)) {
                    logMissingClaimValue(clientId, key, isCustomAttribute);
                    continue;
                }
                claimsBuilder.claim(resolvedKey, value);
                LOGGER.debug("Added {} claim '{}' for client '{}'",
                        isCustomAttribute ? "custom attribute" : "mandatory field", resolvedKey, clientId);
            } catch (Exception ex) {
                LOGGER.error("Client '{}': error adding custom claim '{}'", clientId, key, ex);
            }
        }
    }

    /**
     * Logs a warning for a claim key that resolved to no value. Unprefixed keys only match the
     * fixed set in {@link #resolveMandatoryFieldClaim} (e.g. NOT {@code firstName}/{@code lastName},
     * which live in {@code additionalAttributes}), so the message hints at the {@code ATTR_} prefix.
     *
     * @param clientId         the OAuth2 client ID (used for logging)
     * @param key              the original, unresolved claim key (including any prefix)
     * @param isCustomAttribute whether the key was resolved as a custom/dynamic attribute
     */
    private void logMissingClaimValue(String clientId, String key, boolean isCustomAttribute) {
        if (isCustomAttribute) {
            LOGGER.warn("Client '{}': custom attribute claim key '{}' not found or empty", clientId, key);
        } else {
            LOGGER.warn("Client '{}': mandatory field claim key '{}' not recognised or empty. "
                            + "If this is a dynamic/custom attribute, prefix it with {} (e.g. {}{})",
                    clientId, key, CUSTOM_ATTRIBUTE_CLAIM_PREFIX, CUSTOM_ATTRIBUTE_CLAIM_PREFIX, key);
        }
    }

    /**
     * Looks up a custom/dynamic signup attribute value by name.
     *
     * @param additionalAttributes the user's dynamic attribute map (may be null or empty)
     * @param key                  the attribute name (already stripped of the {@code ATTR_} prefix)
     * @return the attribute value, or {@code null} if absent
     */
    private Object resolveCustomAttributeClaim(Map<String, Object> additionalAttributes, String key) {
        return CollectionUtils.isEmpty(additionalAttributes) ? null : additionalAttributes.get(key);
    }

    /**
     * Resolves a mandatory/core {@link UserDetailsResponse} field by name (case-insensitive).
     * The supported field names are hardcoded here since the full set of mandatory user fields
     * eligible for claims is fixed and small (id, userName, email, accountId, status, tenantId,
     * lastSuccessfulLoginTime, mfaRequired); an unrecognised name simply resolves to {@code null}
     * and is logged by the caller.
     *
     * @param userDetailsResponse the user's details
     * @param key                 the mandatory field name (e.g. {@code userName}, {@code email})
     * @return the field value, or {@code null} if the name is not a recognised mandatory field
     */
    private Object resolveMandatoryFieldClaim(UserDetailsResponse userDetailsResponse, String key) {
        return switch (key.toLowerCase(Locale.ROOT)) {
            case "id" -> userDetailsResponse.getId();
            case "username" -> userDetailsResponse.getUserName();
            case "email" -> userDetailsResponse.getEmail();
            case "accountid" -> userDetailsResponse.getAccountId();
            case "status" -> userDetailsResponse.getStatus();
            case "tenantid" -> userDetailsResponse.getTenantId();
            case "lastsuccessfullogintime" -> userDetailsResponse.getLastSuccessfulLoginTime();
            case "mfarequired" -> userDetailsResponse.getMfaRequired();
            default -> null;
        };
    }

    /**
     * This method sets standard claims for the JWT token. Standard claims are
     * additional information that are included in the JWT token. The claims are set
     * based on the tenant properties.
     *
     * @param claimsBuilder JwtClaimsSet.Builder used to build the JWT claims set.
     */
    private void setStandardClaims(JwtClaimsSet.Builder claimsBuilder) {
        LOGGER.debug("## setStandardClaims - START");
        TenantProperties tenantProperties = getCurrentTenantProperties();
        claimsBuilder.claim(JwtClaimNames.JTI, UUID.randomUUID().toString())
                .claim(CLAIM_ACCOUNT_ID, tenantProperties.getAccount().getAccountId())
                .claim(CLAIM_TENANT_ID, tenantProperties.getTenantId());
        LOGGER.debug("## setStandardClaims - END");
    }

    /**
     * Populates the scopeSet with all user scopes when {@code tenant.client.portal-scopeless-user-scopes} is
     * {@code true} and the requested scopeSet is empty (i.e., a scopeless / portal user flow).
     * In that case, all scopes assigned to the user are merged into the scopeSet so that
     * they are included in both the {@code scope} and {@code scopes} claims of the JWT.
     *
     * @param clientDetails       The registered client details (may be null).
     * @param userDetailsResponse The user details containing the user's assigned scopes.
     * @param scopeSet            The current scope set derived from the token request.
     * @return The (possibly enriched) scope set to use for claim population.
     */
    private Set<String> populateUserScopes(UserDetailsResponse userDetailsResponse,
                                           Set<String> scopeSet,
                                           boolean isFederatedUser) {
        LOGGER.debug("## populateUserScopes - START");
        if (isFederatedUser && userDetailsResponse != null
                && !CollectionUtils.isEmpty(userDetailsResponse.getScopes())) {
            // ScopeRoleClaimMappingService already resolved the final scope onto
            // userDetailsResponse - it may deliberately differ from the raw client request
            // (e.g. EXTERNAL/BOTH), so it always wins here, blank request or not.
            scopeSet = new java.util.HashSet<>(userDetailsResponse.getScopes());
            LOGGER.debug("populateUserScopes: scope-role-mapping resolved scopeSet={}", scopeSet);
            LOGGER.debug("## populateUserScopes - END");
            return scopeSet;
        }

        TenantProperties tenantProperties = getCurrentTenantProperties();
        Boolean portalScopelessUserScopes = tenantProperties.getClient().getAuthCodeScopelessUserScopes();
        if (Boolean.TRUE.equals(portalScopelessUserScopes)
                && userDetailsResponse != null
                && !CollectionUtils.isEmpty(userDetailsResponse.getScopes())) {
            LOGGER.debug("portal-scopeless-user-scopes=true: merging user scopes into scopeSet");
            if (CollectionUtils.isEmpty(scopeSet)) {
                scopeSet = new java.util.HashSet<>(userDetailsResponse.getScopes());
            }
            LOGGER.debug("populateUserScopes: merged scopeSet={}", scopeSet);
        } else {
            LOGGER.debug("portal-scopeless-user-scopes=false or user scopes empty, no scope enrichment");
        }
        LOGGER.debug("## populateUserScopes - END");
        return scopeSet;
    }

    /**
     * This method adds scope and scopes to the JWT claims. The scopes are added
     * based on the registered client details, user details response, and the grant
     * type. The method handles different scenarios based on whether the grant type
     * is client credentials or not.
     *
     * @param registeredClientDetails      RegisteredClientDetails containing the
     *                                     details of the registered client.
     * @param userDetailsResponse          UserDetailsResponse containing the
     *                                     details of the user.
     * @param claimsBuilder                JwtClaimsSet.Builder used to build the
     *                                     JWT claims set.
     * @param scopeSet                     Set of scopes associated with the token.
     * 
     * @param isClientCredentialsGrantType boolean indicating if the grant type is
     *                                     client credentials.
     * @param isFederatedUser boolean indicating if the principal authenticated via
     *                                     an external IDP (federated login) 
     *                                     {@link #addScopeAndScopesForNotClientCredsGrantType}.
     */
    private void addScopeAndScopes(ClientCacheDetails clientDetails,
                                   UserDetailsResponse userDetailsResponse,
                                   JwtClaimsSet.Builder claimsBuilder,
                                   Set<String> scopeSet,
                                   boolean isClientCredentialsGrantType,
                                   boolean isFederatedUser) {
        LOGGER.debug("## addScopeAndScopes - START");
        TenantProperties tenantProperties = getCurrentTenantProperties();
        if (CommonMethodsUtils.isUserScopeValidationRequired(
                (null != clientDetails ? clientDetails.getClientType() : null),
                tenantProperties.getClient().getOauthScopeCustomization()
        )) {
            LOGGER.debug("Scope and Scopes bifurcation not required - "
                    + "Single Role Client or tenant.client.oauth-scope-customization = false");
            addScopeAndScopesForSingleRoleClient(claimsBuilder, scopeSet);
        } else if (clientDetails != null) {
            LOGGER.debug("Scope and Scopes bifurcation required - Multi Role Client"
                    + " or tenant.client.oauth-scope-customization = true");
            addScopeAndScopesForMultiRoleClient(clientDetails, userDetailsResponse, claimsBuilder,
                    scopeSet, isClientCredentialsGrantType, isFederatedUser);
        } else {
            LOGGER.warn("ClientDetails is null, skipping scope and scopes bifurcation for multi-role client");
        }
        LOGGER.debug("## addScopeAndScopes - END");
    }

    /**
     * This method adds scope and scopes to the JWT claims for a single role client.
     * The scopes are added based on the scope set provided. This method is used
     * when scope and scopes bifurcation is not required, i.e., for single role
     * clients or when tenant.client.oauth-scope-customization is set to false.
     *
     * @param claimsBuilder JwtClaimsSet.Builder used to build the JWT claims set.
     * @param scopeSet      Set of scopes associated with the token.
     */
    private void addScopeAndScopesForSingleRoleClient(JwtClaimsSet.Builder claimsBuilder, Set<String> scopeSet) {
        LOGGER.debug("## addScopeAndScopesForSingleRoleClient - START");
        if (!CollectionUtils.isEmpty(scopeSet)) {
            claimsBuilder.claim(OAuth2ParameterNames.SCOPE, String.join(" ", scopeSet)).claim(CLAIM_SCOPES, scopeSet);
        }
        LOGGER.debug("## addScopeAndScopesForSingleRoleClient - END");
    }

    /**
     * This method adds scope and scopes to the JWT claims for a multi-role client.
     * The scopes are added based on the registered client details, user details
     * response, and the grant type. The method handles different scenarios based on
     * whether the grant type is client credentials or not.
     *
     * @param clientDetails RegisteredClientDetails containing the details of the registered client.
     * @param userDetailsResponse UserDetailsResponse containing the details of the user.
     * @param claimsBuilder JwtClaimsSet.Builder used to build the JWT claims set.
     * @param scopeSet Set of scopes associated with the token.
     * @param isClientCredentialsGrantType boolean indicating if the grant type is client credentials.
     * @param isFederatedUser boolean indicating if the principal authenticated via an
     *         external IDP (federated login).
     */
    private void addScopeAndScopesForMultiRoleClient(ClientCacheDetails clientDetails,
                                                     UserDetailsResponse userDetailsResponse,
                                                     JwtClaimsSet.Builder claimsBuilder,
                                                     Set<String> scopeSet,
                                                     boolean isClientCredentialsGrantType,
                                                     boolean isFederatedUser) {
        LOGGER.debug("## addScopeAndScopesForMultiRoleClient - START");
        if (isClientCredentialsGrantType) {
            LOGGER.debug("Grant Type: Client Credentials");
            if (CollectionUtils.isEmpty(clientDetails.getRegisteredClient().getScopes())) {
                // client scope is empty
                LOGGER.info("Client Scopes are empty");
            } else {
                if (CollectionUtils.isEmpty(scopeSet)) {
                    // empty scope request
                    LOGGER.info("Empty scope request");
                    claimsBuilder
                            .claim(OAuth2ParameterNames.SCOPE, String.join(" ",
                                clientDetails.getRegisteredClient().getScopes()))
                            .claim(CLAIM_SCOPES, clientDetails.getRegisteredClient().getScopes());
                } else {
                    if (clientDetails.getRegisteredClient().getScopes().containsAll(scopeSet)) {
                        LOGGER.debug("Requested scopes are subset of client scopes");
                        claimsBuilder
                                .claim(OAuth2ParameterNames.SCOPE, String.join(" ", scopeSet))
                                .claim(CLAIM_SCOPES, clientDetails.getRegisteredClient().getScopes());
                    } else {
                        LOGGER.info("Requested scopes are not subset of client scopes");
                        // handled at line 139 igniteSecurityConfig
                    }
                }
            }
        } else {
            addScopeAndScopesForNotClientCredsGrantType(clientDetails, userDetailsResponse, claimsBuilder, scopeSet,
                    isFederatedUser);
        }
        LOGGER.debug("## addScopeAndScopesForMultiRoleClient - END");
    }

    /**
     * This method adds scope and scopes to the JWT claims for a non
     * client-credentials grant type. The scopes are added based on the registered
     * client details and user details response. This method is used when the grant
     * type is not client credentials.
     *
     * @param clientDetails RegisteredClientDetails containing the details of the registered client.
     * @param userDetailsResponse UserDetailsResponse containing the details of the user.
     * @param claimsBuilder JwtClaimsSet.Builder used to build the JWT claims set.
     * @param scopeSet Set of scopes associated with the token.
     * @param isFederatedUserWithScopeRoleMapping boolean indicating if the principal authenticated via an
     *         external IDP (federated login) with scope-role mapping.
     *         When {@code true} and the requested scope is empty, falls back to the user's
     *         resolved scopes (Rule 2 output on {@code userDetailsResponse}) instead of the
     *         client's full registered scope list.
     */
    private void addScopeAndScopesForNotClientCredsGrantType(ClientCacheDetails clientDetails,
                                                             UserDetailsResponse userDetailsResponse,
                                                             JwtClaimsSet.Builder claimsBuilder, Set<String> scopeSet,
                                                             boolean isFederatedUserWithScopeRoleMapping) {
        LOGGER.debug("Grant Type: Not Client Credentials");
        if (CollectionUtils.isEmpty(clientDetails.getRegisteredClient().getScopes())) {
            logEmptyClientScopes(scopeSet);
            return;
        }
        Set<String> effectiveScopeSet = resolveNotClientCredsScopeSet(clientDetails, userDetailsResponse, scopeSet,
                isFederatedUserWithScopeRoleMapping);
        applyNotClientCredsScopeClaims(claimsBuilder, userDetailsResponse, effectiveScopeSet);
    }

    /**
     * Logs the outcome when the client has no registered scopes at all.
     *
     * @param scopeSet Set of scopes requested for the token.
     */
    private void logEmptyClientScopes(Set<String> scopeSet) {
        if (CollectionUtils.isEmpty(scopeSet)) {
            LOGGER.info("Requested Scopes and client scopes are empty");
        } else {
            LOGGER.debug("Requested Scopes are not empty and Client Scopes are empty");
            // handled at line 139 igniteSecurityConfig
        }
    }

    /**
     * Resolves the scope set to use when the requested scope is empty but the client has
     * registered scopes: falls back to the user's resolved scopes (Rule 2) for federated users
     * with scope-role mapping, otherwise the client's full registered scope list.
     *
     * @param clientDetails ClientCacheDetails containing the details of the registered client.
     * @param userDetailsResponse UserDetailsResponse containing the details of the user.
     * @param scopeSet Set of scopes requested for the token.
     * @param isFederatedUserWithScopeRoleMapping boolean indicating if the principal authenticated via an
     *         external IDP (federated login) with scope-role mapping.
     * @return the scope set to use for building the claims.
     */
    private Set<String> resolveNotClientCredsScopeSet(ClientCacheDetails clientDetails,
            UserDetailsResponse userDetailsResponse, Set<String> scopeSet,
            boolean isFederatedUserWithScopeRoleMapping) {
        if (!CollectionUtils.isEmpty(scopeSet)) {
            return scopeSet;
        }
        if (isFederatedUserWithScopeRoleMapping && userDetailsResponse != null
                && !CollectionUtils.isEmpty(userDetailsResponse.getScopes())) {
            LOGGER.debug("Requested scopes are empty (federated login) - using resolved user scopes "
                    + "(Rule 2) as scope claim instead of full client scope list");
            return userDetailsResponse.getScopes();
        }
        LOGGER.debug("Requested scopes are empty and Client Scopes are not empty");
        return clientDetails.getRegisteredClient().getScopes();
    }

    /**
     * Adds the {@code scope} claim, and the {@code scp} claim when the user has resolved scopes.
     *
     * @param claimsBuilder JwtClaimsSet.Builder used to build the JWT claims set.
     * @param userDetailsResponse UserDetailsResponse containing the details of the user.
     * @param scopeSet Set of scopes to add as the {@code scope} claim.
     */
    private void applyNotClientCredsScopeClaims(JwtClaimsSet.Builder claimsBuilder,
            UserDetailsResponse userDetailsResponse, Set<String> scopeSet) {
        if (userDetailsResponse == null || CollectionUtils.isEmpty(userDetailsResponse.getScopes())) {
            LOGGER.info("User Scopes are empty");
            claimsBuilder
                    .claim(OAuth2ParameterNames.SCOPE, String.join(" ", scopeSet));
        } else {
            LOGGER.debug("User Scopes are not empty");
            claimsBuilder.claim(OAuth2ParameterNames.SCOPE, String.join(" ", scopeSet)).claim(CLAIM_SCOPES,
                    userDetailsResponse.getScopes());
        }
    }

    private void recordScopeRoleMappingOutcome(String tenantId, String idProvider,
            UserDetailsResponse userDetailsResponse, RuntimeException failure) {
        boolean success = failure == null;
        MetricType metricType = success
                ? MetricType.RBAC_SCOPE_MAPPING_SUCCESS
                : MetricType.RBAC_SCOPE_MAPPING_FAILURE;
        try {
            authorizationMetricsService.incrementMetricsForTenantAndIdp(
                    tenantId, idProvider, metricType);
        } catch (RuntimeException ex) {
            LOGGER.warn("Unable to record RBAC metric: metric={}, failureType={}",
                    metricType.getMetricName(), ex.getClass().getSimpleName());
        }

        AuditEventType eventType = success
                ? AuditEventType.RBAC_SCOPE_MAPPING_SUCCEEDED
                : AuditEventType.RBAC_SCOPE_MAPPING_FAILED;
        String failureCode = failure instanceof OAuth2AuthenticationException oauthException
                && oauthException.getError() != null
                ? oauthException.getError().getErrorCode()
                : failure == null ? null : failure.getClass().getSimpleName();
        try {
            TokenAuthenticationContext authorizationContext = TokenAuthenticationContext.builder()
                    .grantType(AUTHORIZATION_CODE_GRANT_TYPE)
                    .authType("idp:" + idProvider)
                    .failureCode(failureCode)
                    .build();
            auditLogger.log(eventType.getType(), COMPONENT_NAME,
                    success ? AuditEventResult.SUCCESS : AuditEventResult.FAILURE,
                    eventType.getDescription(), buildUserActorContext(userDetailsResponse),
                    null, null, authorizationContext);
        } catch (RuntimeException ex) {
            LOGGER.warn("Unable to record RBAC audit event: eventType={}, failureType={}",
                    eventType.getType(), ex.getClass().getSimpleName());
        }
    }

    /**
     * Logs successful authentication via external Identity Provider (IdP).
     * This method is called after a user successfully authenticates through an external IdP
     * and their details are retrieved or created in the system.
     * Note: HttpRequestContext is null for external IdP flows since the actual authentication
     * request goes to the external IdP server, not our authorization server.
     *
     * @param userDetailsResponse The user details retrieved or created after IDP authentication
     * @param oauth2AuthenticationToken The OAuth2 authentication token containing IdP information and claims
     */
    private void logIdpAuthenticationSuccess(UserDetailsResponse userDetailsResponse,
                                            OAuth2AuthenticationToken oauth2AuthenticationToken) {
        try {
            // Extract IdP registration ID (with tenant prefix)
            String tenantPrefixedRegistrationId = oauth2AuthenticationToken.getAuthorizedClientRegistrationId();
            
            // Extract just the IdP name (e.g., "google" from "demo-google")
            String idpRegistrationId = tenantPrefixedRegistrationId;
            if (tenantPrefixedRegistrationId != null && tenantPrefixedRegistrationId.contains("-")) {
                String[] parts = tenantPrefixedRegistrationId.split("-", TENANT_PREFIX_PARTS);
                if (parts.length == TENANT_PREFIX_PARTS) {
                    idpRegistrationId = parts[1];
                }
            }
            
            // Extract IdP claims
            Map<String, Object> idpClaims = oauth2AuthenticationToken.getPrincipal().getAttributes();
            
            final UserActorContext actorContext = UserActorContext.builder()
                .userId(userDetailsResponse.getId())
                .username(userDetailsResponse.getUserName())
                .accountId(userDetailsResponse.getAccountId())
                .accountName(null) // External IDP users may not have account name
                .build();
            
            // HttpRequestContext is null for external IdP flows since the authentication
            // request goes to the external IdP, not our server
            final HttpRequestContext requestContext = null;
            
            auditLogger.log(
                AuditEventType.AUTH_SUCCESS_IDP.getType(),
                COMPONENT_NAME,
                AuditEventResult.SUCCESS,
                AuditEventType.AUTH_SUCCESS_IDP.getDescription(),
                actorContext,
                requestContext
            );
            
            LOGGER.debug("Audit log created for AUTH_SUCCESS_IDP: userId={}, idp={}", 
                        userDetailsResponse.getId(), idpRegistrationId);
        } catch (Exception e) {
            LOGGER.error("Failed to create audit log for AUTH_SUCCESS_IDP: {}", e.getMessage(), e);
        }
    }

    /**
     * Logs successful token refresh operation.
     * This method is called when a new access token is issued using the refresh_token grant type.
     * Only called when grant_type=refresh_token, so the principal will always be either:
     * 1. Password-authenticated users (CustomUserPwdAuthenticationToken)
     * 2. IdP-authenticated users (OAuth2AuthenticationToken)
     * Note: HttpRequestContext is null since token customizers don't have direct access to HTTP request.
     *
     * @param context The JWT encoding context containing grant type and principal information
     * @param userDetailsResponse The user details retrieved for the refresh token request
     * @param clientDetails The client details for the OAuth2 client requesting the token
     */
    private void logTokenRefreshed(JwtEncodingContext context, 
                                   UserDetailsResponse userDetailsResponse,
                                   ClientCacheDetails clientDetails) {
        try {
            Object principal = context.getPrincipal();
            final UserActorContext actorContext;
            final String authType;
            
            if (principal instanceof CustomUserPwdAuthenticationToken) {
                // Password-authenticated user token refresh
                authType = "password";
                actorContext = buildUserActorContext(userDetailsResponse);
            } else if (principal instanceof OAuth2AuthenticationToken oauth2Token) {
                // IdP-authenticated user token refresh
                String idpName = extractIdpName(oauth2Token);
                authType = "idp:" + idpName;
                actorContext = buildUserActorContext(userDetailsResponse);
            } else {
                // Unexpected principal type - log warning and return early
                LOGGER.warn("Unexpected principal type for TOKEN_REFRESHED: {}", 
                           principal != null ? principal.getClass().getName() : "null");
                return;
            }
            
            TokenAuthenticationContext tokenAuthContext = TokenAuthenticationContext.builder()
                .grantType("refresh_token")
                .authType(authType)
                .clientId(clientDetails != null ? clientDetails.getRegisteredClient().getClientId() : null)
                .build();
            
            auditLogger.log(
                AuditEventType.TOKEN_REFRESHED.getType(),
                COMPONENT_NAME,
                AuditEventResult.SUCCESS,
                AuditEventType.TOKEN_REFRESHED.getDescription(),
                actorContext,
                null,  // TargetContext
                null,  // RequestContext - null for token customizer flows
                tokenAuthContext
            );
            
            LOGGER.debug("Audit log created for TOKEN_REFRESHED: authType={}", authType);
        } catch (Exception e) {
            LOGGER.error("Failed to create audit log for TOKEN_REFRESHED: {}", e.getMessage(), e);
        }
    }

    /**
     * Logs access token generation for initial token issuance (authorization_code, client_credentials).
     * This method is called when an access token is generated for:
     * 1. authorization_code - Initial token for password or IdP authenticated users
     * 2. client_credentials - Service account token
     * Note: HttpRequestContext is null since token customizers don't have direct access to HTTP request.
     *
     * @param context The JWT encoding context containing grant type and principal information
     * @param userDetailsResponse The user details (null for client_credentials grant)
     * @param clientDetails The client details for the OAuth2 client requesting the token
     * @param grantType The OAuth2 grant type used to obtain the token
     */
    private void logAccessTokenGenerated(JwtEncodingContext context,
                                        UserDetailsResponse userDetailsResponse,
                                        ClientCacheDetails clientDetails,
                                        String grantType) {
        try {
            final UserActorContext actorContext;
            final String authType;
            
            if (CLIENT_CREDENTIALS_GRANT_TYPE.equals(grantType)) {
                // Client credentials flow - service account
                authType = "client_credentials";
                actorContext = buildClientActorContext(clientDetails);
            } else {
                // authorization_code flow - password or IdP user
                Object principal = context.getPrincipal();
                if (principal instanceof CustomUserPwdAuthenticationToken) {
                    authType = "password";
                    actorContext = buildUserActorContext(userDetailsResponse);
                } else if (principal instanceof OAuth2AuthenticationToken oauth2Token) {
                    String idpName = extractIdpName(oauth2Token);
                    authType = "idp:" + idpName;
                    actorContext = buildUserActorContext(userDetailsResponse);
                } else {
                    LOGGER.warn("Unexpected principal type for ACCESS_TOKEN_GENERATED: {}", 
                               principal != null ? principal.getClass().getName() : "null");
                    return;
                }
            }
            
            TokenAuthenticationContext tokenAuthContext = TokenAuthenticationContext.builder()
                .grantType(grantType)
                .authType(authType)
                .clientId(clientDetails != null ? clientDetails.getRegisteredClient().getClientId() : null)
                .build();
            
            auditLogger.log(
                AuditEventType.ACCESS_TOKEN_GENERATED.getType(),
                COMPONENT_NAME,
                AuditEventResult.SUCCESS,
                AuditEventType.ACCESS_TOKEN_GENERATED.getDescription(),
                actorContext,
                null,  // TargetContext
                null,  // RequestContext - null for token customizer flows
                tokenAuthContext
            );
            
            LOGGER.debug("Audit log created for ACCESS_TOKEN_GENERATED: grantType={}, authType={}", 
                        grantType, authType);
        } catch (Exception e) {
            LOGGER.error("Failed to create audit log for ACCESS_TOKEN_GENERATED: {}", e.getMessage(), e);
        }
    }

    /**
     * Builds UserActorContext from user details.
     *
     * @param userDetailsResponse The user details
     * @return UserActorContext for audit logging
     */
    private UserActorContext buildUserActorContext(UserDetailsResponse userDetailsResponse) {
        return UserActorContext.builder()
            .userId(userDetailsResponse.getId())
            .username(userDetailsResponse.getUserName())
            .accountId(userDetailsResponse.getAccountId())
            .accountName(null)
            .build();
    }

    /**
     * Builds UserActorContext from client details (for client_credentials flow).
     *
     * @param clientDetails The client details
     * @return UserActorContext for audit logging
     */
    private UserActorContext buildClientActorContext(ClientCacheDetails clientDetails) {
        return UserActorContext.builder()
            .userId(null)
            .username(clientDetails.getRegisteredClient().getClientId())
            .accountId(clientDetails.getAccountId())
            .accountName(clientDetails.getAccountName())
            .build();
    }

    /**
     * Extracts IdP name from OAuth2AuthenticationToken.
     *
     * @param oauth2Token The OAuth2 authentication token
     * @return The IdP name (e.g., "google" from "demo-google")
     */
    private String extractIdpName(OAuth2AuthenticationToken oauth2Token) {
        String tenantPrefixedRegistrationId = oauth2Token.getAuthorizedClientRegistrationId();
        if (tenantPrefixedRegistrationId != null && tenantPrefixedRegistrationId.contains("-")) {
            String[] parts = tenantPrefixedRegistrationId.split("-", TENANT_PREFIX_PARTS);
            if (parts.length == TENANT_PREFIX_PARTS) {
                return parts[1];
            }
        }
        return tenantPrefixedRegistrationId;
    }

    /**
     * This method retrieves an OAuth2TokenCustomizer implementation to customize
     * the OAuth 2.0 Token attributes contained within the OAuth2TokenClaimsContext.
     *
     * @return OAuth2TokenCustomizer The customizer used to modify the OAuth 2.0
     *         Token attributes.
     */
    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
        return context -> {
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                // Customize headers/claims for access_token
                LOGGER.debug("Claims added to opaque Access token");
            } else if (context.getTokenType().equals(OAuth2TokenType.REFRESH_TOKEN)) {
                // Customize headers/claims for refresh_token
                LOGGER.debug("Claims added to opaque Refresh token");
            }
        };
    }

    /**
     * This method checks if the authenticated principal is a federated user (authenticated via an external IdP)
     * and if scope-role mapping is enabled for that IdP. It returns true if both conditions are met, otherwise false.
     *
     * @param principal the authenticated principal to check; may be any {@link Authentication} implementation,
     *                  not just federated logins (e.g. username/password logins use a different implementation)
     * @return true if the principal is a federated user with scope-role mapping enabled, false otherwise
     */
    private boolean isFederatedUser(Authentication principal) {
        LOGGER.debug("## isFederatedUser - START");
        if (!(principal instanceof OAuth2AuthenticationToken oauth2Token)) {
            LOGGER.debug("isFederatedUser: principal is not federated "
                    + "(not an OAuth2AuthenticationToken), returning false");
            return false;
        }
        return true;
    }
}
