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

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.ecsp.oauth2.server.core.authentication.customizer.FederatedIdentityIdTokenCustomizer;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.PasswordUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * The AuthorizationServerConfig class is a configuration class that manages authorization server configurations. This
 * class has been refactored to support multiple tenants by using dynamic tenant property resolution.
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationServerConfig.class);

    @Value("${ignite.oauth2.issuer.protocol:http}")
    private String issuerProtocol;

    @Value("${ignite.oauth2.issuer.host:localhost}")
    private String issuerHost;

    @Value("${ignite.oauth2.issuer.prefix:}")
    private String issuerPrefix;

    @Value("${security.client.bcrypt.strength:high}")
    private String bcryptLength;

    private final TenantConfigurationService tenantConfigurationService;

    /**
     * Constructor for AuthorizationServerConfig. It initializes the tenant configuration service for dynamic tenant
     * property resolution.
     *
     * @param tenantConfigurationService the service to retrieve tenant properties
     */
    public AuthorizationServerConfig(TenantConfigurationService tenantConfigurationService) {
        this.tenantConfigurationService = tenantConfigurationService;
    }

    /**
     * Creates a tenant-aware JWKSource that resolves keys dynamically based on current tenant. This component retrieves
     * the appropriate JWK configuration for each tenant at runtime.
     *
     * @param keyStoreConfigByPubPvtKey Configuration for KeyStore by Public and Private Key
     * @param keyStoreConfigByJavaKeyStore Configuration for KeyStore by Java KeyStore
     * @return TenantAwareJWKSource A tenant-aware source of JSON Web Keys (JWKs)
     */
    @Bean
    @Primary
    public JWKSource<SecurityContext> jwkSource(KeyStoreConfigByPubPvtKey keyStoreConfigByPubPvtKey,
            KeyStoreConfigByJavaKeyStore keyStoreConfigByJavaKeyStore) {
        return new TenantAwareJwkSource(tenantConfigurationService, keyStoreConfigByPubPvtKey,
                keyStoreConfigByJavaKeyStore);
    }

    /**
     * This method creates a NimbusJwtEncoder instance using the provided JWKSource. NimbusJwtEncoder is a JWT encoder
     * for encoding OAuth 2.0 Tokens as a JSON Web Token (JWT).
     *
     * @param jwkSource JSON Web Key (JWK) source. Exposes a method for retrieving JWKs matching a specified selector.
     * @return NimbusJwtEncoder instance for encoding OAuth 2.0 Tokens as a JWT.
     */
    @Bean
    NimbusJwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * This method creates an OAuth2TokenGenerator instance using the provided JwtEncoder, jwtCustomizer, and
     * opaqueAccessTokenCustomizer. OAuth2TokenGenerator is a token generator for generating OAuth 2.0 Tokens - JWT and
     * Opaque(Access and Refresh).
     *
     * @param jwtEncoder JWT Encoder for encoding OAuth 2.0 Tokens as a JWT.
     * @param jwtCustomizer Implementations of this interface are responsible for customizing the OAuth 2.0 Token
     *        attributes contained within the JwtEncodingContext.
     * @param opaqueAccessTokenCustomizer Implementations of this interface are responsible for customizing the OAuth
     *        2.0 Token attributes contained within the OAuth2TokenClaimsContext.
     * @return OAuth2TokenGenerator instance for generating OAuth 2.0 Tokens.
     */
    @Bean
    OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer,
            OAuth2TokenCustomizer<OAuth2TokenClaimsContext> opaqueAccessTokenCustomizer) {
        LOGGER.debug("## tokenGenerator - START");
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        accessTokenGenerator.setAccessTokenCustomizer(opaqueAccessTokenCustomizer);
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        LOGGER.debug("## tokenGenerator - END");
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    /**
     * This method creates a JwtDecoder instance using the provided JWKSource. JwtDecoder is a JWT decoder for decoding
     * JSON Web Tokens (JWT) into Jwt objects.
     *
     * @param jwkSource JSON Web Key (JWK) source. Exposes a method for retrieving JWKs matching a specified selector.
     * @return JwtDecoder instance for decoding JSON Web Tokens into Jwt objects.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * This method creates an AuthorizationServerSettings instance. AuthorizationServerSettings is a settings class for
     * the authorization server. It includes configurations for the issuer URL.
     *
     * @return AuthorizationServerSettings instance with the issuer URL set.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer(buildIssuerBaseUrl()).build();
    }

    /**
     * This method creates an OAuth2TokenCustomizer instance for JwtEncodingContext. OAuth2TokenCustomizer is an
     * interface for customizing the OAuth 2.0 Token attributes contained within the JwtEncodingContext.
     *
     * @return OAuth2TokenCustomizer instance for customizing the OAuth 2.0 Token attributes.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
        return new FederatedIdentityIdTokenCustomizer();
    }

    /**
     * This method constructs the issuer base URL. The issuer base URL is a combination of the issuer protocol, issuer
     * host, and issuer prefix. It is used as the issuer URL in the OAuth 2.0 tokens.
     *
     * @return String representing the issuer base URL.
     */
    private String buildIssuerBaseUrl() {

        if (StringUtils.isEmpty(issuerPrefix)) {
            issuerPrefix = StringUtils.EMPTY;
        }

        return issuerProtocol + "://" + issuerHost + issuerPrefix;
    }

    /**
     * This method creates an instance of PasswordEncoder.
     *
     * @return a PasswordEncoder for client secret password encoding.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(PasswordUtils.UIDAM_BCRYPT_STRENGTH_MAP.get(bcryptLength));
    }
}
