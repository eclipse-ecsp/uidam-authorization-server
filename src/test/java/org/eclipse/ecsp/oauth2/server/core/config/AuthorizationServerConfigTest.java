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

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Test class for AuthorizationServerConfig. This class tests the multi-tenant configuration
 * for authorization server components, especially the JWK source configuration.
 */
@ExtendWith(MockitoExtension.class)
class AuthorizationServerConfigTest {

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

    private AuthorizationServerConfig authorizationServerConfig;

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
            jwtEncoder, jwtCustomizer, opaqueAccessTokenCustomizer);

        // Assert
        assertNotNull(result);
        assertInstanceOf(OAuth2TokenGenerator.class, result);
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
    void testAuthorizationServerSettings_ShouldConfigureIssuerUrl() {
        // Act
        AuthorizationServerSettings result = authorizationServerConfig.authorizationServerSettings();

        // Assert
        assertNotNull(result);
        assertEquals("https://localhost/oauth2", result.getIssuer());
    }

    @Test
    void testAuthorizationServerSettings_WithEmptyPrefix_ShouldConfigureIssuerUrl() {
        // Arrange
        ReflectionTestUtils.setField(authorizationServerConfig, "issuerPrefix", "");

        // Act
        AuthorizationServerSettings result = authorizationServerConfig.authorizationServerSettings();

        // Assert
        assertNotNull(result);
        assertEquals("https://localhost", result.getIssuer());
    }

    @Test
    void testAuthorizationServerSettings_WithNullPrefix_ShouldConfigureIssuerUrl() {
        // Arrange
        ReflectionTestUtils.setField(authorizationServerConfig, "issuerPrefix", null);

        // Act
        AuthorizationServerSettings result = authorizationServerConfig.authorizationServerSettings();

        // Assert
        assertNotNull(result);
        assertEquals("https://localhost", result.getIssuer());
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
            jwtEncoder, jwtCustomizer, opaqueAccessTokenCustomizer);

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
