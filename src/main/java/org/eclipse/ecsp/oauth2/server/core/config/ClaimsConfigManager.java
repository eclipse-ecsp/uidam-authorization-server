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

import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
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
    private static final Logger LOGGER = LoggerFactory.getLogger(ClaimsConfigManager.class);

    private final TenantConfigurationService tenantConfigurationService;
    private final UserManagementClient userManagementClient;
    private final ClaimMappingService claimMappingService;

    /**
     * Constructor for ClaimsConfigManager. It initializes the tenant configuration service
     * for dynamic tenant resolution.
     *
     * @param tenantConfigurationService the service to retrieve tenant properties from
     * @param claimMappingService the service for claim mapping operations
     * @param userManagementClient the client for user management operations
     */
    @Autowired
    public ClaimsConfigManager(TenantConfigurationService tenantConfigurationService,
            ClaimMappingService claimMappingService,
            UserManagementClient userManagementClient) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.claimMappingService = claimMappingService;
        this.userManagementClient = userManagementClient;
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
            // Need to refactor
            UserDetailsResponse userDetailsResponse = null;
            if (AUTHORIZATION_CODE_GRANT_TYPE.equals(context.getAuthorizationGrantType().getValue())
                    || REFRESH_TOKEN_GRANT_TYPE.equals(context.getAuthorizationGrantType().getValue())) {
                if (context.getPrincipal() instanceof CustomUserPwdAuthenticationToken
                    customUserPwdAuthenticationToken) {
                    LOGGER.debug("Non Federated user authentication");
                    userDetailsResponse = userManagementClient.getUserDetailsByUsername(
                            customUserPwdAuthenticationToken.getName(),
                            customUserPwdAuthenticationToken.getAccountName());
                }
                if (context.getPrincipal() instanceof OAuth2AuthenticationToken oauth2AuthenticationToken) {
                    LOGGER.debug("Federated user authentication");
                    userDetailsResponse = getUserDetailsForFederatedUser(oauth2AuthenticationToken);
                }
            }
            JwtClaimsSet.Builder claimsBuilder = context.getClaims();
            Set<String> scopeSet = claimsBuilder.build().getClaim(OAuth2ParameterNames.SCOPE);
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {

                ClientCacheDetails clientDetails = cacheClientUtils.getClientDetails(
                    context.getRegisteredClient().getClientId());
                addClaimsForAccessToken(context, clientDetails, userDetailsResponse, claimsBuilder, scopeSet);
            } else if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                addClaimsForIdToken(context, userDetailsResponse, claimsBuilder);
            }
        };
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
        String idpRegisteredClientId = oauth2AuthenticationToken.getAuthorizedClientRegistrationId();
        ExternalIdpRegisteredClient idpClient = findExternalIdpClient(idpRegisteredClientId);
        
        if (idpClient == null) {
            throw new OAuth2AuthenticationException(
                new OAuth2Error(
                    "invalid_idp_configuration",
                    "No external IDP configuration found for: " + idpRegisteredClientId,
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
        String federatedUserName = idpRegisteredClientId + "_" + userName;

        return getFederatedUserDetails(idpRegisteredClientId, federatedUserName, idpClient, claims);
    }

    /**
     * Finds the external Identity Provider (IdP) client configuration based on the registration ID.
     * This method searches through the tenant's configured external IdP clients to find a matching
     * registration.
     *

     * @param idpRegisteredClientId The registration ID of the external IdP client to find
     * @return ExternalIdpRegisteredClient The matching IdP client configuration, or null if not found
     */
    private ExternalIdpRegisteredClient findExternalIdpClient(String idpRegisteredClientId) {
        TenantProperties tenantProperties = getCurrentTenantProperties();
        return tenantProperties.getExternalIdpRegisteredClientList().stream()
                .filter(x -> x.getRegistrationId().equalsIgnoreCase(idpRegisteredClientId))
                .findFirst()
                .orElse(null);
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
        if (StringUtils.hasText(clientDetails.getTenantId())) {
            claimsBuilder
                    .claim(CLAIM_TENANT_ID, clientDetails.getTenantId());
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
        if (StringUtils.hasText(userDetailsResponse.getTenantId())) {
            claimsBuilder.claim(CLAIM_TENANT_ID, userDetailsResponse.getTenantId());
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

