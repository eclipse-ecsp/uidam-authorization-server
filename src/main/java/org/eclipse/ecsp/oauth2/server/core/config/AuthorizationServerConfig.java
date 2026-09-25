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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.audit.context.TokenAuthenticationContext;
import org.eclipse.ecsp.oauth2.server.core.audit.context.UserActorContext;
import org.eclipse.ecsp.oauth2.server.core.audit.enums.AuditEventType;
import org.eclipse.ecsp.oauth2.server.core.authentication.customizer.FederatedIdentityIdTokenCustomizer;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.metrics.MetricType;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.token.PublicClientAwareRefreshTokenGenerator;
import org.eclipse.ecsp.oauth2.server.core.utils.PasswordUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


/**
 * The AuthorizationServerConfig class is a configuration class that manages authorization server configurations. This
 * class has been refactored to support multiple tenants by using dynamic tenant property resolution.
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationServerConfig.class);
    private static final String COMPONENT_NAME = "UIDAM_AUTHORIZATION_SERVER";
    private static final String UNKNOWN_VALUE = "unknown";

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
     * @param metricsService authorization metrics service
     * @param auditLogger persistent security audit logger
     * @return OAuth2TokenGenerator instance for generating OAuth 2.0 Tokens.
     */
    @Bean
    OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer,
            OAuth2TokenCustomizer<OAuth2TokenClaimsContext> opaqueAccessTokenCustomizer,
            AuthorizationMetricsService metricsService, AuditLogger auditLogger) {
        LOGGER.debug("## tokenGenerator - START");
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        accessTokenGenerator.setAccessTokenCustomizer(opaqueAccessTokenCustomizer);
        PublicClientAwareRefreshTokenGenerator refreshTokenGenerator = new PublicClientAwareRefreshTokenGenerator();

        LOGGER.debug("## tokenGenerator - END");
        OAuth2TokenGenerator<Jwt> idTokenAwareJwtGenerator = context ->
                generateJwt(jwtGenerator, context, metricsService, auditLogger);
        return new DelegatingOAuth2TokenGenerator(
                idTokenAwareJwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    Jwt generateJwt(JwtGenerator jwtGenerator, OAuth2TokenContext context,
            AuthorizationMetricsService metricsService, AuditLogger auditLogger) {
        if (context == null || context.getTokenType() == null
                || !OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            return jwtGenerator.generate(context);
        }

        recordIdTokenMetric(metricsService, MetricType.ID_TOKEN_GENERATION_INITIATED);
        LOGGER.debug("ID token generation initiated: clientId={}", clientId(context));
        try {
            Jwt jwt = jwtGenerator.generate(context);
            if (jwt == null) {
                recordIdTokenFailure(context, metricsService, auditLogger, "NO_TOKEN_GENERATED");
            } else {
                recordIdTokenMetric(metricsService, MetricType.ID_TOKEN_GENERATION_SUCCESS);
                writeIdTokenAudit(context, auditLogger, AuditEventType.ID_TOKEN_GENERATED,
                        AuditEventResult.SUCCESS, null);
                LOGGER.debug("ID token generation succeeded: clientId={}", clientId(context));
            }
            return jwt;
        } catch (RuntimeException | Error ex) {
            recordIdTokenFailure(context, metricsService, auditLogger, ex.getClass().getSimpleName());
            throw ex;
        }
    }

    private void recordIdTokenFailure(OAuth2TokenContext context, AuthorizationMetricsService metricsService,
            AuditLogger auditLogger, String failureCode) {
        recordIdTokenMetric(metricsService, MetricType.ID_TOKEN_GENERATION_FAILURE);
        writeIdTokenAudit(context, auditLogger, AuditEventType.ID_TOKEN_GENERATION_FAILED,
                AuditEventResult.FAILURE, failureCode);
        LOGGER.error("ID token generation failed: clientId={}, failureCode={}", clientId(context), failureCode);
    }

    private void recordIdTokenMetric(AuthorizationMetricsService metricsService, MetricType metricType) {
        try {
            String tenantId = UNKNOWN_VALUE;
            TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
            if (tenantProperties != null) {
                tenantId = tenantProperties.getTenantId();
            }
            metricsService.incrementMetricsForTenant(
                    StringUtils.defaultIfBlank(tenantId, UNKNOWN_VALUE), metricType);
        } catch (RuntimeException ex) {
            LOGGER.warn("Unable to record ID token metric: metric={}, failureType={}",
                    metricType.getMetricName(), ex.getClass().getSimpleName());
        }
    }

    private void writeIdTokenAudit(OAuth2TokenContext context, AuditLogger auditLogger,
            AuditEventType eventType, AuditEventResult result, String failureCode) {
        try {
            Authentication principal = context.getPrincipal();
            UserActorContext actorContext = UserActorContext.builder()
                    .username(principal == null ? null : principal.getName())
                    .build();
            TokenAuthenticationContext authenticationContext = TokenAuthenticationContext.builder()
                    .grantType(context.getAuthorizationGrantType() == null
                            ? null : context.getAuthorizationGrantType().getValue())
                    .authType(authenticationType(principal))
                    .clientId(clientId(context))
                    .scopes(context.getAuthorizedScopes() == null
                            ? null : String.join(" ", context.getAuthorizedScopes()))
                    .failureCode(failureCode)
                    .build();
            auditLogger.log(eventType.getType(), COMPONENT_NAME, result, eventType.getDescription(),
                    actorContext, null, null, authenticationContext);
        } catch (RuntimeException ex) {
            LOGGER.warn("Unable to write ID token audit event: eventType={}, failureType={}",
                    eventType.getType(), ex.getClass().getSimpleName());
        }
    }

    private String authenticationType(Authentication principal) {
        if (principal instanceof CustomUserPwdAuthenticationToken) {
            return "password";
        }
        if (principal instanceof OAuth2AuthenticationToken oauth2Token) {
            return "idp:" + oauth2Token.getAuthorizedClientRegistrationId();
        }
        return UNKNOWN_VALUE;
    }

    private String clientId(OAuth2TokenContext context) {
        return context.getRegisteredClient() == null ? UNKNOWN_VALUE : context.getRegisteredClient().getClientId();
    }

    /**
     * This method creates a JwtDecoder instance using the provided JWKSource. JwtDecoder is a JWT decoder for decoding
     * JSON Web Tokens (JWT) into Jwt objects.
     *
     * <p>Accepts this server's {@code at+jwt} access tokens, including the full media type allowed by
     * RFC 9068, while retaining legacy {@code JWT}/absent typing. Spring's default type validator
     * rejects access-token typing. Both validation layers use the same allow-list; signature,
     * timestamp and certificate binding checks remain enabled. The UserInfo provider separately
     * requires an active, stored access token with {@code openid} scope and an associated ID token.
     *
     * @param jwkSource JSON Web Key (JWK) source. Exposes a method for retrieving JWKs matching a specified selector.
     * @return JwtDecoder instance for decoding JSON Web Tokens into Jwt objects.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();
        jwsAlgorithms.addAll(JWSAlgorithm.Family.RSA);
        jwsAlgorithms.addAll(JWSAlgorithm.Family.EC);
        jwsAlgorithms.addAll(JWSAlgorithm.Family.HMAC_SHA);
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(jwsAlgorithms, jwkSource);

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        String accessTokenType = IgniteOauth2CoreConstants.CLAIM_HEADER_JWT_ACCESS_TOKEN_TYPE;
        String accessTokenMediaType = "application/" + accessTokenType;
        jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(
                new JOSEObjectType(accessTokenType),
                new JOSEObjectType(accessTokenMediaType),
                JOSEObjectType.JWT,
                null));
        // Override the default Nimbus claims set verifier as NimbusJwtDecoder handles it instead.
        jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> { });

        NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(jwtProcessor);
        // NimbusJwtDecoder's own default jwtValidator (JwtValidators.createDefault()) includes a
        // JwtTypeValidator that only accepts typ=JWT or absent, independent of the JWS-level type
        // verifier configured above. Replace just the type check within that validator chain so
        // at+jwt access tokens pass, while keeping the other default validators (timestamp, x5t#S256).
        JwtTypeValidator typeValidator = new JwtTypeValidator(List.of(
                accessTokenType, accessTokenMediaType, JOSEObjectType.JWT.getType()));
        typeValidator.setAllowEmpty(true);
        jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithValidators(List.of(typeValidator)));

        return jwtDecoder;
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
     * This method creates an AuthorizationServerSettings instance.
     * AuthorizationServerSettings is a settings class for the authorization server.
     * It includes configurations for the issuer URL.
     *
     * @return AuthorizationServerSettings instance with the endpoint set set.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .jwkSetEndpoint("/oauth2/jwks")
                .oidcUserInfoEndpoint("/oauth2/userinfo")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .multipleIssuersAllowed(true)
                .build();

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
