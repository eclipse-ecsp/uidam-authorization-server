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
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.metrics.MetricType;
import org.eclipse.ecsp.oauth2.server.core.request.dto.FederatedUserDto;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.service.ClaimMappingService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.AUTHORIZATION_CODE_GRANT_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_ACCOUNT_ID;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_ACCOUNT_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_FIRST_NAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_HEADER_ID_TOKEN_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_HEADER_JWT_ACCESS_TOKEN_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_HEADER_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_LAST_LOGON;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_LAST_NAME;
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

    private static final Logger LOGGER = LoggerFactory.getLogger(ClaimsConfigManager.class);

    private final TenantConfigurationService tenantConfigurationService;
    private final UserManagementClient userManagementClient;
    private final ClaimMappingService claimMappingService;
    private final AuthorizationMetricsService authorizationMetricsService;
    private final AuditLogger auditLogger;

    /**
     * Constructor for ClaimsConfigManager. It initializes the tenant configuration service
     * for dynamic tenant resolution.
     *
     * @param tenantConfigurationService the service to retrieve tenant properties from
     * @param claimMappingService the service for claim mapping operations
     * @param userManagementClient the client for user management operations
     * @param authorizationMetricsService the service for authorization metrics
     * @param auditLogger the audit logger
     */
    @Autowired
    public ClaimsConfigManager(TenantConfigurationService tenantConfigurationService,
            ClaimMappingService claimMappingService,
            UserManagementClient userManagementClient,
            AuthorizationMetricsService authorizationMetricsService,
            AuditLogger auditLogger) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.claimMappingService = claimMappingService;
        this.userManagementClient = userManagementClient;
        this.authorizationMetricsService = authorizationMetricsService;
        this.auditLogger = auditLogger;
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
            UserDetailsResponse userDetailsResponse = retrieveUserDetails(context);
            
            JwtClaimsSet.Builder claimsBuilder = context.getClaims();
            Set<String> scopeSet = claimsBuilder.build().getClaim(OAuth2ParameterNames.SCOPE);
            
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                processAccessToken(context, cacheClientUtils, userDetailsResponse, claimsBuilder, scopeSet);
            } else if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                addClaimsForIdToken(context, userDetailsResponse, claimsBuilder);
            }
        };
    }

    /**
     * Retrieves user details based on the authentication context.
     * Supports both internal password authentication and federated authentication.
     *
     * @param context The JWT encoding context
     * @return UserDetailsResponse or null if not applicable
     */
    private UserDetailsResponse retrieveUserDetails(JwtEncodingContext context) {
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
            return getUserDetailsForFederatedUser(oauth2AuthenticationToken);
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
     * @return UserDetailsResponse containing the details of the federated user.
     */
    private UserDetailsResponse getUserDetailsForFederatedUser(OAuth2AuthenticationToken oauth2AuthenticationToken) {
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
        if (AUTHORIZATION_CODE_GRANT_TYPE.equals(context.getAuthorizationGrantType().getValue())) {
            setUserCustomClaims(claimsBuilder, userDetailsResponse);
            addScopeAndScopes(clientDetails, userDetailsResponse, claimsBuilder, scopeSet, false);
            LOGGER.debug("Claims added to JWT Access token for grant type - authorization_code");
        } else if (CLIENT_CREDENTIALS_GRANT_TYPE.equals(context.getAuthorizationGrantType().getValue())) {
            setClientCustomClaims(clientDetails, claimsBuilder);
            addScopeAndScopes(clientDetails, null, claimsBuilder, scopeSet, true);
            LOGGER.debug("Claims added to JWT Access token for grant type - client_credentials");
        } else if (REFRESH_TOKEN_GRANT_TYPE.equals(context.getAuthorizationGrantType().getValue())) {
            setUserCustomClaims(claimsBuilder, userDetailsResponse);
            addScopeAndScopes(clientDetails, null, claimsBuilder, scopeSet, false);
            LOGGER.debug("Claims added to JWT Access token for grant type - refresh_token");
        }
    }

    /**
     * This method adds claims to the ID token. Claims are additional information
     * about the user that are included in the ID token. The claims are customized
     * based on the context and user details response.
     *
     * @param context             JwtEncodingContext containing the OAuth 2.0 JWT
     *                            Token attributes.
     * @param userDetailsResponse UserDetailsResponse containing the details of the
     *                            user.
     */
    private void addClaimsForIdToken(JwtEncodingContext context, UserDetailsResponse userDetailsResponse,
            JwtClaimsSet.Builder claimsBuilder) {

        context.getJwsHeader().header(CLAIM_HEADER_TYPE, CLAIM_HEADER_ID_TOKEN_TYPE);

        claimsBuilder.claim(JwtClaimNames.JTI, UUID.randomUUID().toString())
                .claim(CLAIM_USER_ID, userDetailsResponse.getId())
                .claim(CLAIM_USERNAME, userDetailsResponse.getUserName());
        Map<String, Object> additionalAttributes = userDetailsResponse.getAdditionalAttributes();
        if (!CollectionUtils.isEmpty(additionalAttributes)) {
            LOGGER.debug("Adding claims from additional attributes");
            for (Map.Entry<String, Object> entry : additionalAttributes.entrySet()) {
                if (additionalAttributes.containsKey(CLAIM_FIRST_NAME) && !ObjectUtils.isEmpty(entry.getValue())) {
                    claimsBuilder.claim(CLAIM_FIRST_NAME, entry.getValue());
                }
                if (additionalAttributes.containsKey(CLAIM_LAST_NAME) && !ObjectUtils.isEmpty(entry.getValue())) {
                    claimsBuilder.claim(CLAIM_LAST_NAME, entry.getValue());
                }
            }
        }
        LOGGER.debug("Added claims from additional attributes");
        LOGGER.debug("Claims added to ID token");
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
    private void setUserCustomClaims(JwtClaimsSet.Builder claimsBuilder, UserDetailsResponse userDetailsResponse) {
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
        if (!CollectionUtils.isEmpty(additionalAttributes)) {
            LOGGER.info("Adding claims from additional attributes");
            List<String> additionalClaimsAttributesList;
            TenantProperties tenantProperties = getCurrentTenantProperties();
            for (Map.Entry<String, Object> entry : additionalAttributes.entrySet()) {
                if (Objects.nonNull(tenantProperties) && Objects.nonNull(tenantProperties.getUser())
                        && Objects.nonNull(tenantProperties.getUser().getJwtAdditionalClaimAttributes())) {
                    additionalClaimsAttributesList = Arrays.asList(tenantProperties.getUser()
                            .getJwtAdditionalClaimAttributes().replaceAll("\\s", "").split(COMMA_DELIMITER));
                    if (additionalClaimsAttributesList.contains(entry.getKey())) {
                        claimsBuilder.claim(entry.getKey(), entry.getValue());
                        LOGGER.debug("Added claims from additional attributes");
                    }
                }
            }
        }

        LOGGER.debug("## setUserCustomClaims - END");
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
     */
    private void addScopeAndScopes(ClientCacheDetails clientDetails,
                                   UserDetailsResponse userDetailsResponse,
                                   JwtClaimsSet.Builder claimsBuilder,
                                   Set<String> scopeSet,
                                   boolean isClientCredentialsGrantType) {
        LOGGER.debug("## addScopeAndScopes - START");
        TenantProperties tenantProperties = getCurrentTenantProperties();
        if (CommonMethodsUtils.isUserScopeValidationRequired(
                (null != clientDetails ? clientDetails.getClientType() : null),
                tenantProperties.getClient().getOauthScopeCustomization()
        )) {
            LOGGER.debug("Scope and Scopes bifurcation not required - "
                    + "Single Role Client or tenant.client.oauth-scope-customization = false");
            addScopeAndScopesForSingleRoleClient(claimsBuilder, scopeSet);
        } else {
            LOGGER.debug("Scope and Scopes bifurcation required - Multi Role Client"
                    + " or tenant.client.oauth-scope-customization = true");
            addScopeAndScopesForMultiRoleClient(clientDetails, userDetailsResponse, claimsBuilder,
                    scopeSet, isClientCredentialsGrantType);
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
     */
    private void addScopeAndScopesForMultiRoleClient(ClientCacheDetails clientDetails,
                                                     UserDetailsResponse userDetailsResponse,
                                                     JwtClaimsSet.Builder claimsBuilder,
                                                     Set<String> scopeSet,
                                                     boolean isClientCredentialsGrantType) {
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
            addScopeAndScopesForNotClientCredsGrantType(clientDetails, userDetailsResponse, claimsBuilder, scopeSet);
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
     */
    private void addScopeAndScopesForNotClientCredsGrantType(ClientCacheDetails clientDetails,
                                                             UserDetailsResponse userDetailsResponse,
                                                             JwtClaimsSet.Builder claimsBuilder, Set<String> scopeSet) {
        LOGGER.debug("Grant Type: Not Client Credentials");
        if (CollectionUtils.isEmpty(clientDetails.getRegisteredClient().getScopes())) {
            if (CollectionUtils.isEmpty(scopeSet)) {
                LOGGER.info("Requested Scopes and client scopes are empty");
            } else {
                LOGGER.debug("Requested Scopes are not empty and Client Scopes are empty");
                // handled at line 139 igniteSecurityConfig
            }
        } else {
            if (CollectionUtils.isEmpty(scopeSet)) {
                LOGGER.debug("Requested scopes are empty and Client Scopes are not empty");
                scopeSet = clientDetails.getRegisteredClient().getScopes();
            }
            if (CollectionUtils.isEmpty(userDetailsResponse.getScopes())) {
                LOGGER.info("User Scopes are empty");
                claimsBuilder
                        .claim(OAuth2ParameterNames.SCOPE, String.join(" ", scopeSet));
            } else {
                LOGGER.debug("User Scopes are not empty");
                claimsBuilder.claim(OAuth2ParameterNames.SCOPE, String.join(" ", scopeSet)).claim(CLAIM_SCOPES,
                        userDetailsResponse.getScopes());
            }
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
}

