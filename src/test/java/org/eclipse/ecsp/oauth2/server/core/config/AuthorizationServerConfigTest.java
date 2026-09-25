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

package org.eclipse.ecsp.oauth2.server.core.config;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.audit.enums.AuditEventType;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.metrics.MetricType;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.test.util.ReflectionTestUtils;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Test class for AuthorizationServerConfig. This class tests the multi-tenant configuration
 * for authorization server components, especially the JWK source configuration.
 */
@ExtendWith(MockitoExtension.class)
class AuthorizationServerConfigTest {

    private static final int RSA_KEY_SIZE_BITS = 2048;
    private static final long TOKEN_EXPIRY_SECONDS = 3600;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private KeyStoreConfigByPubPvtKey keyStoreConfigByPubPvtKey;

    @Mock
    private KeyStoreConfigByJavaKeyStore keyStoreConfigByJavaKeyStore;

    @Mock
    private TenantAwareJwkSource tenantAwareJwkSource;

    @Mock
    private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

    @Mock
    private OAuth2TokenCustomizer<OAuth2TokenClaimsContext> opaqueAccessTokenCustomizer;
    @Mock
    private AuthorizationMetricsService metricsService;

    @Mock
    private AuditLogger auditLogger;


    private AuthorizationServerConfig authorizationServerConfig;

    private RSAKey signingKey;

    @BeforeEach
    void setUp() {
        authorizationServerConfig = new AuthorizationServerConfig(tenantConfigurationService);
        
        // Set up default values for @Value fields
        ReflectionTestUtils.setField(authorizationServerConfig, "issuerProtocol", "https");
        ReflectionTestUtils.setField(authorizationServerConfig, "issuerHost", "localhost");
        ReflectionTestUtils.setField(authorizationServerConfig, "issuerPrefix", "/oauth2");
        ReflectionTestUtils.setField(authorizationServerConfig, "bcryptLength", "high");
    }

    @Test
    void testConstructor_ShouldInitializeTenantConfigurationService() {
        // Assert
        assertNotNull(authorizationServerConfig);
        assertEquals(tenantConfigurationService, 
                     ReflectionTestUtils.getField(authorizationServerConfig, "tenantConfigurationService"));
    }

    @Test
    void testJwkSource_ShouldCreateTenantAwareJwkSource() {
        // Act
        JWKSource<SecurityContext> result = authorizationServerConfig.jwkSource(
            keyStoreConfigByPubPvtKey, keyStoreConfigByJavaKeyStore);

        // Assert
        assertNotNull(result);
        assertInstanceOf(TenantAwareJwkSource.class, result);
    }

    @Test
    void testJwtEncoder_ShouldCreateNimbusJwtEncoder() {
        // Arrange
        @SuppressWarnings("unchecked")
        JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);

        // Act
        NimbusJwtEncoder result = authorizationServerConfig.jwtEncoder(jwkSource);

        // Assert
        assertNotNull(result);
        assertInstanceOf(NimbusJwtEncoder.class, result);
    }

    @Test
    void testTokenGenerator_ShouldCreateOauth2TokenGenerator() {
        // Arrange
        JwtEncoder jwtEncoder = mock(JwtEncoder.class);

        // Act
        OAuth2TokenGenerator<?> result = authorizationServerConfig.tokenGenerator(
            jwtEncoder, jwtCustomizer, opaqueAccessTokenCustomizer, metricsService, auditLogger);

        // Assert
        assertNotNull(result);
        assertInstanceOf(OAuth2TokenGenerator.class, result);
    }

    @Test
    void idTokenGenerationRecordsSuccessAndReturnsGeneratedToken() {
        JwtGenerator jwtGenerator = mock(JwtGenerator.class);
        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        Jwt expectedJwt = mock(Jwt.class);
        TenantProperties tenantProperties = mock(TenantProperties.class);
        when(context.getTokenType()).thenReturn(new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        when(jwtGenerator.generate(context)).thenReturn(expectedJwt);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantId()).thenReturn("tenant-1");

        Jwt result = authorizationServerConfig.generateJwt(
                jwtGenerator, context, metricsService, auditLogger);

        assertSame(expectedJwt, result);
        verify(metricsService).incrementMetricsForTenant(
                "tenant-1", MetricType.ID_TOKEN_GENERATION_INITIATED);
        verify(metricsService).incrementMetricsForTenant(
                "tenant-1", MetricType.ID_TOKEN_GENERATION_SUCCESS);
        verify(auditLogger).log(
                eq(AuditEventType.ID_TOKEN_GENERATED.getType()),
                anyString(),
                eq(AuditEventResult.SUCCESS),
                anyString(), any(), any(), any(), any());
    }

    @Test
    void idTokenGenerationRecordsFailureAndRethrowsOriginalException() {
        JwtGenerator jwtGenerator = mock(JwtGenerator.class);
        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        TenantProperties tenantProperties = mock(TenantProperties.class);
        IllegalStateException expectedFailure = new IllegalStateException("signing failed");
        when(context.getTokenType()).thenReturn(new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        when(jwtGenerator.generate(context)).thenThrow(expectedFailure);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantId()).thenReturn("tenant-1");

        IllegalStateException actualFailure = assertThrows(IllegalStateException.class,
                () -> authorizationServerConfig.generateJwt(
                        jwtGenerator, context, metricsService, auditLogger));

        assertSame(expectedFailure, actualFailure);
        verify(metricsService).incrementMetricsForTenant(
                "tenant-1", MetricType.ID_TOKEN_GENERATION_FAILURE);
        verify(auditLogger).log(
                eq(AuditEventType.ID_TOKEN_GENERATION_FAILED.getType()),
                anyString(),
                eq(AuditEventResult.FAILURE),
                anyString(), any(), any(), any(), any());
    }

    @Test
    void observabilityFailureDoesNotPreventIdTokenGeneration() {
        JwtGenerator jwtGenerator = mock(JwtGenerator.class);
        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        Jwt expectedJwt = mock(Jwt.class);
        TenantProperties tenantProperties = mock(TenantProperties.class);
        when(context.getTokenType()).thenReturn(new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        when(jwtGenerator.generate(context)).thenReturn(expectedJwt);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantId()).thenReturn("tenant-1");
        doThrow(new IllegalStateException("metrics unavailable"))
                .when(metricsService).incrementMetricsForTenant(
                        "tenant-1", MetricType.ID_TOKEN_GENERATION_INITIATED);
        doThrow(new IllegalStateException("audit unavailable"))
                .when(auditLogger).log(anyString(), anyString(), any(), anyString(),
                        any(), any(), any(), any());

        Jwt result = authorizationServerConfig.generateJwt(
                jwtGenerator, context, metricsService, auditLogger);

        assertSame(expectedJwt, result);
    }

    @Test
    void nonIdTokenGenerationDoesNotInvokeIdTokenObservability() {
        JwtGenerator jwtGenerator = mock(JwtGenerator.class);
        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        Jwt expectedJwt = mock(Jwt.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        when(jwtGenerator.generate(context)).thenReturn(expectedJwt);

        Jwt result = authorizationServerConfig.generateJwt(
                jwtGenerator, context, metricsService, auditLogger);

        assertSame(expectedJwt, result);
        verifyNoInteractions(metricsService, auditLogger, tenantConfigurationService);
    }

    @Test
    void testJwtDecoder_ShouldCreateJwtDecoder() {
        // Arrange
        @SuppressWarnings("unchecked")
        JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);

        // Act
        JwtDecoder result = authorizationServerConfig.jwtDecoder(jwkSource);

        // Assert
        assertNotNull(result);
        assertInstanceOf(JwtDecoder.class, result);
    }

    @Test
    void testJwtDecoder_ShouldAcceptAccessTokenTypedAtPlusJwt() throws Exception {
        // Arrange: a token signed with header typ=at+jwt, as minted by ClaimsConfigManager
        // for access tokens per RFC 9068. Nimbus's default type verifier would reject this.
        JwtDecoder jwtDecoder = authorizationServerConfig.jwtDecoder(rsaJwkSource());
        String token = signJwt("at+jwt");

        // Act
        Jwt decoded = jwtDecoder.decode(token);

        // Assert
        assertNotNull(decoded);
        assertEquals("at+jwt", decoded.getHeaders().get("typ"));
    }

    @Test
    void testJwtDecoder_ShouldAcceptLegacyJwtType() throws Exception {
        // Retain conventional JWT typing for compatibility, independent of token purpose.
        JwtDecoder jwtDecoder = authorizationServerConfig.jwtDecoder(rsaJwkSource());
        String token = signJwt("JWT");

        // Act
        Jwt decoded = jwtDecoder.decode(token);

        // Assert
        assertNotNull(decoded);
        assertEquals("JWT", decoded.getHeaders().get("typ"));
    }

    @Test
    void testJwtDecoder_ShouldRejectUnexpectedTokenType() throws Exception {
        // Arrange: explicit typing (RFC 8725) must still reject unrelated/unexpected typ values.
        JwtDecoder jwtDecoder = authorizationServerConfig.jwtDecoder(rsaJwkSource());
        String token = signJwt("evil-type");

        // Act & Assert
        assertThrows(BadJwtException.class, () -> jwtDecoder.decode(token));
    }

    private JWKSource<SecurityContext> rsaJwkSource() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(RSA_KEY_SIZE_BITS);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID("test-key-id")
                .build();
        this.signingKey = rsaKey;
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    private String signJwt(String typeHeader) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType(typeHeader))
                .keyID(this.signingKey.getKeyID())
                .build();
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("test-user")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(TOKEN_EXPIRY_SECONDS)))
                .build();
        SignedJWT signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(new RSASSASigner(this.signingKey.toRSAPrivateKey()));
        return signedJwt.serialize();
    }

    @Test
    void testAuthorizationServerSettings_ShouldConfigureIssuerUrl() {
        // Act
        AuthorizationServerSettings result = authorizationServerConfig.authorizationServerSettings();

        // Assert
        assertNotNull(result);
        assertEquals("/oauth2/authorize", result.getAuthorizationEndpoint());
        assertEquals("/oauth2/userinfo", result.getOidcUserInfoEndpoint());
    }

    @Test
    void testIdTokenCustomizer_ShouldCreateFederatedIdentityIdTokenCustomizer() {
        // Act
        OAuth2TokenCustomizer<JwtEncodingContext> result = authorizationServerConfig.idTokenCustomizer();

        // Assert
        assertNotNull(result);
        // Since FederatedIdentityIdTokenCustomizer is the specific implementation,
        // we can check the class name
        assertEquals("FederatedIdentityIdTokenCustomizer", result.getClass().getSimpleName());
    }

    @Test
    void testPasswordEncoder_ShouldCreateBcryptPasswordEncoder() {
        // Act
        PasswordEncoder result = authorizationServerConfig.passwordEncoder();

        // Assert
        assertNotNull(result);
        assertInstanceOf(PasswordEncoder.class, result);
    }

    @Test
    void testPasswordEncoder_WithDifferentStrengths_ShouldCreateBcryptPasswordEncoder() {
        // Test with different bcrypt strengths
        String[] strengths = {"low", "medium", "high"};
        
        for (String strength : strengths) {
            // Arrange
            ReflectionTestUtils.setField(authorizationServerConfig, "bcryptLength", strength);

            // Act
            PasswordEncoder result = authorizationServerConfig.passwordEncoder();

            // Assert
            assertNotNull(result);
            assertInstanceOf(PasswordEncoder.class, result);
        }
    }

    @Test
    void testMultiTenantJwkSourceIntegration_ShouldWorkWithAllComponents() {
        // This test verifies that the multi-tenant JWK configuration works end-to-end
        
        // Act - Get JWK source bean (which creates TenantAwareJwkSource internally)
        JWKSource<SecurityContext> jwkSource = authorizationServerConfig.jwkSource(
            keyStoreConfigByPubPvtKey, keyStoreConfigByJavaKeyStore);

        // Create dependent beans
        NimbusJwtEncoder jwtEncoder = authorizationServerConfig.jwtEncoder(jwkSource);

        // Assert - Verify all components are properly configured
        assertNotNull(jwkSource);
        assertNotNull(jwtEncoder);
        JwtDecoder jwtDecoder = authorizationServerConfig.jwtDecoder(jwkSource);
        assertNotNull(jwtDecoder);

        // Verify that JWK source is the tenant-aware implementation
        assertInstanceOf(TenantAwareJwkSource.class, jwkSource);
    }

    @Test
    void testBeanDependencies_ShouldBeProperlyWired() {
        // This test ensures that the Spring bean dependencies are correctly configured
        
        // Act - Create JWK source bean
        JWKSource<SecurityContext> jwkSource = authorizationServerConfig.jwkSource(
            keyStoreConfigByPubPvtKey, keyStoreConfigByJavaKeyStore);

        // Create dependent beans
        NimbusJwtEncoder jwtEncoder = authorizationServerConfig.jwtEncoder(jwkSource);
        JwtDecoder jwtDecoder = authorizationServerConfig.jwtDecoder(jwkSource);
        OAuth2TokenGenerator<?> tokenGenerator = authorizationServerConfig.tokenGenerator(
            jwtEncoder, jwtCustomizer, opaqueAccessTokenCustomizer, metricsService, auditLogger);

        // Assert
        assertNotNull(jwtEncoder);
        assertNotNull(jwtDecoder);
        assertNotNull(tokenGenerator);
    }

    @Test
    void testTenantAwareConfiguration_ShouldNotCallTenantPropertiesAtBeanCreation() {
        // This test ensures that tenant properties are not resolved during bean creation
        // which is critical for multi-tenant support

        // Act - Create beans (this should not call tenant configuration service)
        JWKSource<SecurityContext> jwkSource = authorizationServerConfig.jwkSource(
            keyStoreConfigByPubPvtKey, keyStoreConfigByJavaKeyStore);

        // Assert - Verify no tenant properties were resolved during bean creation
        verifyNoInteractions(tenantConfigurationService);
        assertNotNull(jwkSource);
        assertInstanceOf(TenantAwareJwkSource.class, jwkSource);
    }
}
