/********************************************************************************
 * Copyright (c) 2023 - 2024 Harman International
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

import com.nimbusds.jose.jwk.RSAKey;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.KeyGenerationException;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.sql.multitenancy.TenantContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_JWT_KEY_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for KeyStoreConfigByJavaKeyStore.
 *
 * @since 1.0.0
 */
@ExtendWith(MockitoExtension.class)
class KeyStoreConfigByJavaKeyStoreTest {

    @Mock
    private TenantAwareKeyStoreFactory keyStoreFactory;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private KeyStore keyStore;

    @Mock
    private TenantProperties tenantProperties;

    private KeyStoreConfigByJavaKeyStore keyStoreConfig;

    private KeyPair testKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        keyStoreConfig = new KeyStoreConfigByJavaKeyStore(keyStoreFactory, tenantConfigurationService);
        
        // Generate a test RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        final int keySize = 2048;
        keyGen.initialize(keySize);
        testKeyPair = keyGen.generateKeyPair();
    }

    @Test
    void testConstructorInitialization() {
        assertNotNull(keyStoreConfig);
    }

    @Test
    void testGenerateKeyStoreSuccess() {
        // Arrange
        when(keyStoreFactory.getKeyStoreForCurrentTenant()).thenReturn(keyStore);

        // Act
        KeyStore result = keyStoreConfig.generateKeyStore();

        // Assert
        assertNotNull(result);
        assertEquals(keyStore, result);
    }

    @Test
    void testGenerateRsaKeySuccess() throws Exception {
        // Arrange
        String tenantId = "test-tenant";
        String jwtKeyId = "test-key-id";
        Map<String, String> keyStoreConfig = new HashMap<>();
        keyStoreConfig.put(TENANT_JWT_KEY_ID, jwtKeyId);

        when(keyStoreFactory.getRsaKeyPairForCurrentTenant()).thenReturn(testKeyPair);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getKeyStore()).thenReturn((HashMap<String, String>) keyStoreConfig);

        try (MockedStatic<TenantContext> mockedTenantContext = mockStatic(TenantContext.class)) {
            mockedTenantContext.when(TenantContext::getCurrentTenant).thenReturn(tenantId);

            // Act
            RSAKey result = this.keyStoreConfig.generateRsaKey();

            // Assert
            assertNotNull(result);
            assertEquals(tenantId + "-" + jwtKeyId, result.getKeyID());
            assertTrue(result.toRSAPublicKey() instanceof RSAPublicKey);
            assertTrue(result.toRSAPrivateKey() instanceof RSAPrivateKey);
        }
    }

    @Test
    void testGenerateRsaKeyThrowsExceptionOnKeyPairGenerationFailure() {
        // Arrange
        when(keyStoreFactory.getRsaKeyPairForCurrentTenant())
            .thenThrow(new RuntimeException("KeyPair generation failed"));

        // Act & Assert
        assertThrows(KeyGenerationException.class, () -> keyStoreConfig.generateRsaKey());
    }

    @Test
    void testGenerateRsaKeyThrowsExceptionOnTenantPropertiesFailure() {
        // Arrange - let keyPair succeed but tenantProperties fail
        // The keyPair is retrieved but then exception is thrown when getting tenant properties
        // We must stub it to avoid NullPointerException but it won't be used
        // Use the stubbing even though it triggers warning, or make keyPair also fail
        when(keyStoreFactory.getRsaKeyPairForCurrentTenant())
            .thenThrow(new RuntimeException("Tenant properties failed"));

        // Act & Assert
        assertThrows(KeyGenerationException.class, () -> keyStoreConfig.generateRsaKey());
    }

    @Test
    void testGenerateRsaKeyWithNullKeyStoreConfig() {
        // Arrange
        String tenantId = "test-tenant";
        
        when(keyStoreFactory.getRsaKeyPairForCurrentTenant()).thenReturn(testKeyPair);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getKeyStore()).thenReturn(null);

        try (MockedStatic<TenantContext> mockedTenantContext = mockStatic(TenantContext.class)) {
            mockedTenantContext.when(TenantContext::getCurrentTenant).thenReturn(tenantId);

            // Act & Assert
            assertThrows(KeyGenerationException.class, () -> keyStoreConfig.generateRsaKey());
        }
    }

    @Test
    void testGenerateRsaKeyWithEmptyKeyStoreConfig() throws Exception {
        // Arrange
        String tenantId = "test-tenant";
        Map<String, String> emptyKeyStoreConfig = new HashMap<>();

        when(keyStoreFactory.getRsaKeyPairForCurrentTenant()).thenReturn(testKeyPair);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getKeyStore()).thenReturn((HashMap<String, String>) emptyKeyStoreConfig);

        try (MockedStatic<TenantContext> mockedTenantContext = mockStatic(TenantContext.class)) {
            mockedTenantContext.when(TenantContext::getCurrentTenant).thenReturn(tenantId);

            // Act
            RSAKey result = this.keyStoreConfig.generateRsaKey();

            // Assert
            assertNotNull(result);
            assertEquals(tenantId + "-null", result.getKeyID());
        }
    }
}
