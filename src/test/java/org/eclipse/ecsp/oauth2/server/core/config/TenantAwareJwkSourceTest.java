/*******************************************************************************
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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.KeyGenerationException;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for TenantAwareJWKSource. This class tests the functionality of tenant-aware JWK source
 * that dynamically resolves keys based on tenant context.
 */
@ExtendWith(MockitoExtension.class)
class TenantAwareJwkSourceTest {

    private static final int EXPECTED_SINGLE_RESULT = 1;
    private static final int EXPECTED_CALL_COUNT_ONCE = 1;
    private static final int EXPECTED_CALL_COUNT_TWICE = 2;

    @Mock
    private TenantConfigurationService tenantConfigurationService;
    
    @Mock
    private KeyStoreConfigByPubPvtKey keyStoreConfigByPubPvtKey;
    
    @Mock
    private KeyStoreConfigByJavaKeyStore keyStoreConfigByJavaKeyStore;
    
    @Mock
    private TenantProperties tenantProperties;
    
    @Mock
    private RSAKey rsaKey;
    
    @Mock
    private RSAPublicKey rsaPublicKey;
    
    @Mock
    private RSAPrivateKey rsaPrivateKey;
    
    @Mock
    private JWKSelector jwkSelector;
    
    @Mock
    private SecurityContext securityContext;

    private TenantAwareJwkSource tenantAwareJwkSource;

    @BeforeEach
    void setUp() {
        tenantAwareJwkSource = new TenantAwareJwkSource(
            tenantConfigurationService,
            keyStoreConfigByPubPvtKey,
            keyStoreConfigByJavaKeyStore
        );
    }

    @Test
    void testGet_WithJksEnabled_ShouldUseJavaKeyStore() throws Exception {
        // Arrange
        String tenantId = "test-tenant";
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantName()).thenReturn(tenantId);
        when(tenantProperties.getJksEnabled()).thenReturn(true);
        when(keyStoreConfigByJavaKeyStore.generateRsaKey()).thenReturn(rsaKey);
        when(jwkSelector.select(any())).thenReturn(List.of(rsaKey));

        // Act
        List<JWK> result = tenantAwareJwkSource.get(jwkSelector, securityContext);

        // Assert
        assertNotNull(result);
        assertEquals(EXPECTED_SINGLE_RESULT, result.size());
        assertEquals(rsaKey, result.get(0));
        verify(keyStoreConfigByJavaKeyStore).generateRsaKey();
        verify(keyStoreConfigByPubPvtKey, never()).generateRsaKey();
    }

    @Test
    void testGet_WithJksDisabled_ShouldUsePublicPrivateKey() throws Exception {
        // Arrange
        String tenantId = "test-tenant";
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantName()).thenReturn(tenantId);
        when(tenantProperties.getJksEnabled()).thenReturn(false);
        when(keyStoreConfigByPubPvtKey.generateRsaKey()).thenReturn(rsaKey);
        when(jwkSelector.select(any())).thenReturn(List.of(rsaKey));

        // Act
        List<JWK> result = tenantAwareJwkSource.get(jwkSelector, securityContext);

        // Assert
        assertNotNull(result);
        assertEquals(EXPECTED_SINGLE_RESULT, result.size());
        assertEquals(rsaKey, result.get(0));
        verify(keyStoreConfigByPubPvtKey).generateRsaKey();
        verify(keyStoreConfigByJavaKeyStore, never()).generateRsaKey();
    }

    @Test
    void testGet_WithNullJksEnabled_ShouldUsePublicPrivateKey() throws Exception {
        // Arrange
        String tenantId = "test-tenant";
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantName()).thenReturn(tenantId);
        when(tenantProperties.getJksEnabled()).thenReturn(null);
        when(keyStoreConfigByPubPvtKey.generateRsaKey()).thenReturn(rsaKey);
        when(jwkSelector.select(any())).thenReturn(List.of(rsaKey));

        // Act
        List<JWK> result = tenantAwareJwkSource.get(jwkSelector, securityContext);

        // Assert
        assertNotNull(result);
        assertEquals(EXPECTED_SINGLE_RESULT, result.size());
        assertEquals(rsaKey, result.get(0));
        verify(keyStoreConfigByPubPvtKey).generateRsaKey();
        verify(keyStoreConfigByJavaKeyStore, never()).generateRsaKey();
    }

    @Test
    void testGet_WithMultipleTenants_ShouldCachePerTenant() throws Exception {
        // Arrange
        final String tenant1 = "tenant-1";
        final String tenant2 = "tenant-2";
        final RSAKey rsaKey1 = mock(RSAKey.class);
        final RSAKey rsaKey2 = mock(RSAKey.class);
        
        // First tenant setup
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantName()).thenReturn(tenant1);
        when(tenantProperties.getJksEnabled()).thenReturn(false);
        when(keyStoreConfigByPubPvtKey.generateRsaKey()).thenReturn(rsaKey1);
        when(jwkSelector.select(any())).thenReturn(List.of(rsaKey1));

        // Act - First tenant
        final List<JWK> result1 = tenantAwareJwkSource.get(jwkSelector, securityContext);

        // Switch to second tenant
        when(tenantProperties.getTenantName()).thenReturn(tenant2);
        when(keyStoreConfigByPubPvtKey.generateRsaKey()).thenReturn(rsaKey2);
        when(jwkSelector.select(any())).thenReturn(List.of(rsaKey2));

        // Act - Second tenant
        List<JWK> result2 = tenantAwareJwkSource.get(jwkSelector, securityContext);
        
        // Assert
        assertNotNull(result1);
        assertNotNull(result2);
        assertEquals(rsaKey1, result1.get(0));
        assertEquals(rsaKey2, result2.get(0));
        
        // Verify that generateRsaKey was called twice (once per tenant)
        verify(keyStoreConfigByPubPvtKey, times(EXPECTED_CALL_COUNT_TWICE)).generateRsaKey();
    }

    @Test
    void testGet_WithSameTenant_ShouldUseCache() throws Exception {
        // Arrange
        String tenantId = "test-tenant";
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantName()).thenReturn(tenantId);
        when(tenantProperties.getJksEnabled()).thenReturn(false);
        when(keyStoreConfigByPubPvtKey.generateRsaKey()).thenReturn(rsaKey);
        when(jwkSelector.select(any())).thenReturn(List.of(rsaKey));

        // Act - Call twice with same tenant
        List<JWK> result1 = tenantAwareJwkSource.get(jwkSelector, securityContext);
        List<JWK> result2 = tenantAwareJwkSource.get(jwkSelector, securityContext);

        // Assert
        assertNotNull(result1);
        assertNotNull(result2);
        assertEquals(rsaKey, result1.get(0));
        assertEquals(rsaKey, result2.get(0));
        
        // Verify that generateRsaKey was called only once (cached)
        verify(keyStoreConfigByPubPvtKey, times(EXPECTED_CALL_COUNT_ONCE)).generateRsaKey();
    }

    @Test
    void testGet_WithNullTenantName_ShouldUseDefaultTenant() throws Exception {
        // Arrange
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantName()).thenReturn(null);
        when(tenantProperties.getJksEnabled()).thenReturn(false);
        when(keyStoreConfigByPubPvtKey.generateRsaKey()).thenReturn(rsaKey);
        when(jwkSelector.select(any())).thenReturn(List.of(rsaKey));

        // Act
        List<JWK> result = tenantAwareJwkSource.get(jwkSelector, securityContext);

        // Assert
        assertNotNull(result);
        assertEquals(EXPECTED_SINGLE_RESULT, result.size());
        assertEquals(rsaKey, result.get(0));
        verify(keyStoreConfigByPubPvtKey).generateRsaKey();
    }

    @Test
    void testGet_WithNoTenantProperties_ShouldThrowException() {
        // Arrange
        when(tenantConfigurationService.getTenantProperties()).thenReturn(null);

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tenantAwareJwkSource.get(jwkSelector, securityContext);
        });

        assertTrue(exception.getMessage().contains("Failed to retrieve JWKs for tenant"));
    }

    @Test
    void testGet_WithKeyGenerationException_ShouldThrowRuntimeException() throws Exception {
        // Arrange
        String tenantId = "test-tenant";
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantName()).thenReturn(tenantId);
        when(tenantProperties.getJksEnabled()).thenReturn(false);
        when(keyStoreConfigByPubPvtKey.generateRsaKey())
            .thenThrow(new KeyGenerationException(new RuntimeException("Key generation failed")));

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            tenantAwareJwkSource.get(jwkSelector, securityContext);
        });

        assertTrue(exception.getMessage().contains("Failed to retrieve JWKs for tenant"));
    }

    @Test
    void testClearCacheForTenant() throws Exception {
        // Arrange
        String tenantId = "test-tenant";
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantName()).thenReturn(tenantId);
        when(tenantProperties.getJksEnabled()).thenReturn(false);
        when(keyStoreConfigByPubPvtKey.generateRsaKey()).thenReturn(rsaKey);
        when(jwkSelector.select(any())).thenReturn(List.of(rsaKey));

        // Act - First call to populate cache
        tenantAwareJwkSource.get(jwkSelector, securityContext);
        verify(keyStoreConfigByPubPvtKey, times(EXPECTED_CALL_COUNT_ONCE)).generateRsaKey();

        // Clear cache for tenant
        tenantAwareJwkSource.clearCacheForTenant(tenantId);

        // Act - Second call should regenerate
        tenantAwareJwkSource.get(jwkSelector, securityContext);

        // Assert
        verify(keyStoreConfigByPubPvtKey, times(EXPECTED_CALL_COUNT_TWICE)).generateRsaKey();
    }

    @Test
    void testClearAllCache() throws Exception {
        // Arrange
        String tenantId = "test-tenant";
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getTenantName()).thenReturn(tenantId);
        when(tenantProperties.getJksEnabled()).thenReturn(false);
        when(keyStoreConfigByPubPvtKey.generateRsaKey()).thenReturn(rsaKey);
        when(jwkSelector.select(any())).thenReturn(List.of(rsaKey));

        // Act - First call to populate cache
        tenantAwareJwkSource.get(jwkSelector, securityContext);
        verify(keyStoreConfigByPubPvtKey, times(EXPECTED_CALL_COUNT_ONCE)).generateRsaKey();

        // Clear all cache
        tenantAwareJwkSource.clearAllCache();

        // Act - Second call should regenerate
        tenantAwareJwkSource.get(jwkSelector, securityContext);

        // Assert
        verify(keyStoreConfigByPubPvtKey, times(EXPECTED_CALL_COUNT_TWICE)).generateRsaKey();
    }

    @Test
    void testImplementsJwkSourceInterface() {
        // Assert
        assertTrue(tenantAwareJwkSource instanceof JWKSource);
    }
}
