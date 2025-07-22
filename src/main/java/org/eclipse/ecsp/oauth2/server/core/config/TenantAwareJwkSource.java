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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.apache.commons.lang3.BooleanUtils;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.KeyGenerationException;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tenant-aware JWKSource implementation that dynamically resolves JSON Web Keys (JWKs)
 * based on the current tenant context. This class caches JWK sets per tenant for performance
 * while ensuring each tenant uses the correct cryptographic keys.
 */
public class TenantAwareJwkSource implements JWKSource<SecurityContext> {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(TenantAwareJwkSource.class);
    
    private final TenantConfigurationService tenantConfigurationService;
    private final KeyStoreConfigByPubPvtKey keyStoreConfigByPubPvtKey;
    private final KeyStoreConfigByJavaKeyStore keyStoreConfigByJavaKeyStore;
    
    // Cache JWK sets per tenant for performance
    private final ConcurrentHashMap<String, JWKSet> tenantJwkCache = new ConcurrentHashMap<>();
    
    /**
     * Constructor for TenantAwareJWKSource.
     *
     * @param tenantConfigurationService   Service to retrieve tenant-specific configuration
     * @param keyStoreConfigByPubPvtKey   Configuration for KeyStore by Public and Private Key
     * @param keyStoreConfigByJavaKeyStore Configuration for KeyStore by Java KeyStore
     */
    public TenantAwareJwkSource(TenantConfigurationService tenantConfigurationService,
                                KeyStoreConfigByPubPvtKey keyStoreConfigByPubPvtKey,
                                KeyStoreConfigByJavaKeyStore keyStoreConfigByJavaKeyStore) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.keyStoreConfigByPubPvtKey = keyStoreConfigByPubPvtKey;
        this.keyStoreConfigByJavaKeyStore = keyStoreConfigByJavaKeyStore;
    }
    
    /**
     * Retrieves JWKs matching the specified selector for the current tenant.
     * This method dynamically resolves the tenant context and returns the appropriate
     * JWK set for that tenant.
     *
     * @param jwkSelector    The JWK selector to match keys against
     * @param securityContext The security context (optional)
     * @return List of matching JWKs for the current tenant
     */
    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) {
        try {
            // Get current tenant properties
            TenantProperties tenantProperties = getCurrentTenantProperties();
            
            // Generate a tenant-specific cache key
            String tenantId = tenantProperties.getTenantName();
            if (tenantId == null) {
                tenantId = "default";
            }
            
            // Get or create JWK set for this tenant
            JWKSet jwkSet = tenantJwkCache.computeIfAbsent(tenantId, k -> createJwkSetForTenant(tenantProperties));
            
            // Apply selector to find matching keys
            return jwkSelector.select(jwkSet);
            
        } catch (Exception e) {
            LOGGER.error("Error retrieving JWKs for tenant", e);
            throw new RuntimeException("Failed to retrieve JWKs for tenant", e);
        }
    }
    
    /**
     * Creates a JWK set for the specified tenant using tenant-specific configuration.
     *
     * @param tenantProperties The tenant properties containing key configuration
     * @return JWKSet containing the tenant's cryptographic keys
     */
    private JWKSet createJwkSetForTenant(TenantProperties tenantProperties) {
        try {
            LOGGER.debug("Creating JWK set for tenant: {}", tenantProperties.getTenantName());
            
            RSAKey rsaKey;
            if (BooleanUtils.isTrue(tenantProperties.getJksEnabled())) {
                LOGGER.debug("Using Java KeyStore configuration for tenant: {}", tenantProperties.getTenantName());
                rsaKey = keyStoreConfigByJavaKeyStore.generateRsaKey();
            } else {
                LOGGER.debug("Using Public/Private Key configuration for tenant: {}", tenantProperties.getTenantName());
                rsaKey = keyStoreConfigByPubPvtKey.generateRsaKey();
            }
            
            return new JWKSet(rsaKey);
            
        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | IOException
                | KeyGenerationException e) {
            LOGGER.error("Failed to create JWK set for tenant: {}", tenantProperties.getTenantName(), e);
            throw new RuntimeException("Failed to create JWK set for tenant: " + tenantProperties.getTenantName(), e);
        }
    }
    
    /**
     * Retrieves the current tenant properties from the TenantConfigurationService.
     *
     * @return TenantProperties for the current tenant
     * @throws IllegalStateException if no tenant properties are found
     */
    private TenantProperties getCurrentTenantProperties() {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        if (tenantProperties == null) {
            throw new IllegalStateException("No tenant properties found for current tenant");
        }
        return tenantProperties;
    }
    
    /**
     * Clears the JWK cache for a specific tenant.
     * This can be useful for cache invalidation scenarios.
     *
     * @param tenantId The tenant ID to clear from cache
     */
    public void clearCacheForTenant(String tenantId) {
        tenantJwkCache.remove(tenantId);
        LOGGER.debug("Cleared JWK cache for tenant: {}", tenantId);
    }
    
    /**
     * Clears the entire JWK cache.
     * This can be useful for complete cache refresh scenarios.
     */
    public void clearAllCache() {
        tenantJwkCache.clear();
        LOGGER.debug("Cleared entire JWK cache");
    }
}
