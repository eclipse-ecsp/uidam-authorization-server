/********************************************************************************
 * Copyright (c) 2023-24 Harman International
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.authentication.providers;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * Authentication provider that handles refresh token requests for public clients (PKCE).
 * Public clients authenticate using only their client_id (no client_secret) and must have
 * been originally authenticated via PKCE (Proof Key for Code Exchange).
 *
 * <p>Security controls enforced:
 * <ul>
 *   <li>Client must be registered with {@link ClientAuthenticationMethod#NONE}</li>
 *   <li>Client must have {@link AuthorizationGrantType#REFRESH_TOKEN} in its authorized grant types</li>
 *   <li>The refresh token must be bound to the requesting client_id</li>
 *   <li>Refresh token rotation is enforced via TokenSettings (reuseRefreshTokens=false)</li>
 * </ul>
 */
public class PublicClientRefreshTokenAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(
            PublicClientRefreshTokenAuthenticationProvider.class);

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final TenantConfigurationService tenantConfigurationService;

    /**
     * Constructor for PublicClientRefreshTokenAuthenticationProvider.
     *
     * @param registeredClientRepository the repository for registered clients
     * @param authorizationService the OAuth2 authorization service
     * @param tenantConfigurationService the tenant configuration service
     */
    public PublicClientRefreshTokenAuthenticationProvider(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            TenantConfigurationService tenantConfigurationService) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tenantConfigurationService, "tenantConfigurationService cannot be null");
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.tenantConfigurationService = tenantConfigurationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken clientAuthentication =
                (OAuth2ClientAuthenticationToken) authentication;

        // Only handle refresh_token grant type for public clients
        String grantType = clientAuthentication.getAdditionalParameters() != null
                ? (String) clientAuthentication.getAdditionalParameters().get(OAuth2ParameterNames.GRANT_TYPE)
                : null;

        if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
            return null;
        }

        // Check if public client refresh token is enabled for the current tenant
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        if (tenantProperties != null && tenantProperties.getClient() != null
                && Boolean.FALSE.equals(tenantProperties.getClient().getPublicClientRefreshTokenEnabled())) {
            LOGGER.debug("Public client refresh token is disabled for current tenant");
            return null;
        }

        Object principal = clientAuthentication.getPrincipal();
        if (principal == null) {
            throwInvalidClient("client_id is required");
        }
        String clientId = principal.toString();
        LOGGER.debug("Authenticating public client for refresh_token grant: {}", clientId);

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throwInvalidClient("Client not found");
        }

        // Verify this is a public client (authentication method = none)
        if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            LOGGER.debug("Client {} is not a public client, skipping", clientId);
            return null;
        }

        // Verify refresh_token grant type is allowed for this client
        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            throwInvalidClient("refresh_token grant type not authorized for client");
        }

        // Validate the refresh token is bound to this client
        String refreshTokenValue = clientAuthentication.getAdditionalParameters() != null
                ? (String) clientAuthentication.getAdditionalParameters().get(OAuth2ParameterNames.REFRESH_TOKEN)
                : null;

        if (refreshTokenValue != null) {
            OAuth2Authorization authorization = authorizationService.findByToken(
                    refreshTokenValue, OAuth2TokenType.REFRESH_TOKEN);
            if (authorization != null && !authorization.getRegisteredClientId().equals(registeredClient.getId())) {
                LOGGER.warn("Refresh token does not belong to client: {}", clientId);
                throwInvalidClient("Refresh token is not bound to this client");
            }
        }

        LOGGER.debug("Public client authenticated for refresh_token grant: {}", clientId);
        OAuth2ClientAuthenticationToken authenticatedToken =
                new OAuth2ClientAuthenticationToken(registeredClient,
                        ClientAuthenticationMethod.NONE, null);
        authenticatedToken.setDetails(clientAuthentication.getDetails());
        return authenticatedToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private void throwInvalidClient(String description) {
        throw new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, description, ERROR_URI));
    }
}
