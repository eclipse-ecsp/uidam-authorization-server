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

package org.eclipse.ecsp.oauth2.server.core.service;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ClientProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails;
import org.eclipse.ecsp.oauth2.server.core.utils.PasswordUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.ConfigurationSettingNames;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ID_PREFIX;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ID_SUFFIX;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.NOOP_ID_ENCODE;

/**
 * Service class for mapping client details to a RegisteredClient instance.
 */
@Service
public class RegisteredClientMapper {

    private static final Logger LOGGER = LoggerFactory.getLogger(RegisteredClientMapper.class);

    private final TenantConfigurationService tenantConfigurationService;
    
    @Value("${security.client.bcrypt.strength:high}")
    private String bcryptLength;

    /**
     * Constructor for RegisteredClientMapper.
     *
     * @param tenantConfigurationService the tenant configuration service
     */
    public RegisteredClientMapper(TenantConfigurationService tenantConfigurationService) {
        this.tenantConfigurationService = tenantConfigurationService;
    }

    /**
     * This method is used to convert client details into a RegisteredClient instance.
     * It sets the client id, client secret, client name, client authentication methods, authorization grant types,
     * redirect URIs, scopes, token settings, and client settings.
     *
     * @param clientDetails the client details to be converted.
     * @return the converted RegisteredClient instance.
     */
    public RegisteredClient toRegisteredClient(RegisteredClientDetails clientDetails) {
        LOGGER.debug("Mapping RegisteredClientDetails to RegisteredClient instance for client id: {}",
            clientDetails.getClientId());
        RegisteredClient.Builder builder = RegisteredClient.withId(clientDetails.getClientId());

        builder.clientId(clientDetails.getClientId());
        setClientSecretEncoded(clientDetails, builder);
        builder.clientName(clientDetails.getClientName());

        setClientAuthenticationMethods(clientDetails, builder);
        setClientAuthorizationGrantTypes(clientDetails, builder);
        setClientRedirectUris(clientDetails, builder);
        setClientScopes(clientDetails, builder);
        builder.tokenSettings(
            tokenSettingsBuilder(clientDetails));

        builder.clientSettings(getClientSettings(clientDetails));
        LOGGER.debug("Mapped RegisteredClientDetails to RegisteredClient instance for client id: {}",
            clientDetails.getClientId());
        return builder.build();
    }

    /**
     * This method is used to set the scopes for a RegisteredClient instance.
     * It checks if the client details have any scopes present. If so, it adds each scope to the RegisteredClient
     * instance.
     *
     * @param clientDetails the client details from which to retrieve the scopes.
     * @param builder the RegisteredClient.Builder instance to which the scopes are added.
     */
    private void setClientScopes(RegisteredClientDetails clientDetails, RegisteredClient.Builder builder) {
        if (Optional.ofNullable(clientDetails.getScopes()).isPresent()) {
            builder.scopes(scopesConsumer -> {
                for (String scope : clientDetails.getScopes()) {
                    scopesConsumer.add(scope);
                }
            });
        }
    }


    /**
     * This method is used to set the redirect URIs for a RegisteredClient instance.
     * It checks if the client details have any redirect URIs or post logout redirect URIs present. If so, it adds
     * each URI to the RegisteredClient instance.
     *
     * @param clientDetails the client details from which to retrieve the redirect URIs.
     * @param builder the RegisteredClient.Builder instance to which the redirect URIs are added.
     */
    private void setClientRedirectUris(RegisteredClientDetails clientDetails, RegisteredClient.Builder builder) {
        if (Optional.ofNullable(clientDetails.getRedirectUris()).isPresent()) {
            builder.redirectUris(redirectUrisConsumer -> {
                for (String redirectUri : clientDetails.getRedirectUris()) {
                    redirectUrisConsumer.add(redirectUri);
                }
            });
        }
        if (Optional.ofNullable(clientDetails.getPostLogoutRedirectUris()).isPresent()) {
            builder.postLogoutRedirectUris(postLogoutRedirectUrisConsumer -> {
                for (String postLogoutRedirectUri : clientDetails.getPostLogoutRedirectUris()) {
                    postLogoutRedirectUrisConsumer.add(postLogoutRedirectUri);
                }
            });
        }
    }

    /**
     * This method is used to set the authorization grant types for a RegisteredClient instance.
     * It checks if the client details have any authorization grant types present. If so, it adds each grant type to the
     * RegisteredClient instance as a new AuthorizationGrantType.
     *
     * @param clientDetails the client details from which to retrieve the authorization grant types.
     * @param builder the RegisteredClient.Builder instance to which the authorization grant types are added.
     */
    private void setClientAuthorizationGrantTypes(RegisteredClientDetails clientDetails,
                                                  RegisteredClient.Builder builder) {
        if (Optional.ofNullable(clientDetails.getAuthorizationGrantTypes()).isPresent()) {
            builder.authorizationGrantTypes(authorizationGrantTypesConsumer -> {
                for (String grantType : clientDetails.getAuthorizationGrantTypes()) {
                    authorizationGrantTypesConsumer.add(new AuthorizationGrantType(grantType));
                }
            });
        }
    }

    /**
     * This method is used to set the client authentication methods for a RegisteredClient instance.
     * It checks if the client details have any client authentication methods present. If so, it adds each
     * authentication method to the RegisteredClient instance as a new ClientAuthenticationMethod.
     *
     * @param clientDetails the client details from which to retrieve the client authentication methods.
     * @param builder the RegisteredClient.Builder instance to which the client authentication methods are added.
     */
    private void setClientAuthenticationMethods(RegisteredClientDetails clientDetails,
                                                RegisteredClient.Builder builder) {
        if (Optional.ofNullable(clientDetails.getClientAuthenticationMethods()).isPresent()) {
            builder.clientAuthenticationMethods(clientAuthenticationMethodsConsumer -> {
                for (String authMethod : clientDetails.getClientAuthenticationMethods()) {
                    clientAuthenticationMethodsConsumer.add(new ClientAuthenticationMethod(authMethod));
                }
            });
        }
    }

    /**
     * Sets the client secret for a RegisteredClient instance.
     * If the client secret is not encoded, it encodes the raw password using BCrypt.
     *
     * @param clientDetails the client details containing the client secret.
     * @param builder the RegisteredClient.Builder instance to which the client secret is set.
     */
    private void setClientSecretEncoded(RegisteredClientDetails clientDetails, RegisteredClient.Builder builder) {
        String clientSecret = clientDetails.getClientSecret();
        String id = extractId(clientSecret);
        if (id == null || id.equals(NOOP_ID_ENCODE)) {
            String rawPassword = extractEncodedPassword(clientSecret);
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(
                    PasswordUtils.UIDAM_BCRYPT_STRENGTH_MAP.get(bcryptLength));
            clientSecret = passwordEncoder.encode(rawPassword);
        }
        builder.clientSecret(clientSecret);
    }

    /**
     * Extracts the ID from a prefix-encoded password.
     *
     * @param prefixEncodedPassword the prefix-encoded password from which to extract the ID.
     * @return the extracted ID, or null if the ID cannot be extracted.
     */
    private String extractId(String prefixEncodedPassword) {
        int start = prefixEncodedPassword.indexOf(ID_PREFIX);
        if (start != 0) {
            return null;
        }
        int end = prefixEncodedPassword.indexOf(ID_SUFFIX, start);
        if (end < 0) {
            return null;
        }
        return prefixEncodedPassword.substring(start + ID_PREFIX.length(), end);
    }

    /**
     * Extracts the encoded password from a prefix-encoded password.
     *
     * @param prefixEncodedPassword the prefix-encoded password from which to extract the encoded password.
     * @return the extracted encoded password.
     */
    private String extractEncodedPassword(String prefixEncodedPassword) {
        int start = prefixEncodedPassword.indexOf(ID_SUFFIX);
        return prefixEncodedPassword.substring(start + ID_SUFFIX.length());
    }

    /**
     * This method is used to build the TokenSettings for a RegisteredClient instance.
     * It retrieves the client details and sets the access token time to live, access token format, authorization code
     * time to live, refresh token time to live, reuse refresh tokens, and id token signature algorithm.
     *
     * @param clientDetails the client details from which to retrieve the token settings.
     * @return the built TokenSettings instance.
     */
    private TokenSettings tokenSettingsBuilder(RegisteredClientDetails clientDetails) {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        ClientProperties clientProperties = tenantProperties.getClient();
        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();
        tokenSettingsBuilder.accessTokenTimeToLive(
            clientDetails.getAccessTokenValidity() != 0 ? Duration.ofSeconds(clientDetails.getAccessTokenValidity())
                : Duration.ofSeconds(clientProperties.getAccessTokenTtl()));
        tokenSettingsBuilder.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED);
        tokenSettingsBuilder.authorizationCodeTimeToLive(clientDetails.getAuthorizationCodeValidity() != 0
            ? Duration.ofSeconds(clientDetails.getAuthorizationCodeValidity())
            : Duration.ofSeconds(clientProperties.getAuthCodeTtl()));
        tokenSettingsBuilder.refreshTokenTimeToLive(clientDetails.getRefreshTokenValidity() != 0
            ? Duration.ofSeconds(clientDetails.getRefreshTokenValidity())
            : Duration.ofSeconds(clientProperties.getRefreshTokenTtl()));
        tokenSettingsBuilder.reuseRefreshTokens(clientProperties.getReuseRefreshToken());
        tokenSettingsBuilder.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256);

        return tokenSettingsBuilder.build();
    }

    /**
     * This method is used to build the ClientSettings for a RegisteredClient instance.
     * It retrieves the client details and sets the require authorization consent and require proof key settings.
     *
     * @param clientDetails the client details from which to retrieve the client settings.
     * @return the built ClientSettings instance.
     */
    private ClientSettings getClientSettings(RegisteredClientDetails clientDetails) {
        Map<String, Object> map = new HashMap<>();

        map.put(ConfigurationSettingNames.Client.REQUIRE_AUTHORIZATION_CONSENT,
            clientDetails.isRequireAuthorizationConsent());
        map.put(ConfigurationSettingNames.Client.REQUIRE_PROOF_KEY,
            clientDetails.isRequireProofKey());

        return ClientSettings.withSettings(map).build();
    }

}