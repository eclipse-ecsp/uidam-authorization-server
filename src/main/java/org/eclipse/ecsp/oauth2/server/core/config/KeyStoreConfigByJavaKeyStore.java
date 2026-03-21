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

import com.nimbusds.jose.jwk.RSAKey;
import org.eclipse.ecsp.oauth2.server.core.exception.KeyGenerationException;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.sql.multitenancy.TenantContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.interfaces.RSAPublicKey;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_JWT_KEY_ID;

/**
 * The KeyStoreConfigByJavaKeyStore class is a configuration class that uses Java KeyStore for generating RSA keys.
 */
@Configuration
public class KeyStoreConfigByJavaKeyStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreConfigByJavaKeyStore.class);

    private final TenantAwareKeyStoreFactory keyStoreFactory;
    
    private final TenantConfigurationService tenantConfigurationService;

    /**
     * Constructor for KeyStoreConfigByJavaKeyStore.
     * Uses factory pattern for tenant-aware operations during request processing.
     *
     * @param keyStoreFactory Factory for tenant-aware KeyStore operations
     */
    public KeyStoreConfigByJavaKeyStore(TenantAwareKeyStoreFactory keyStoreFactory, 
            TenantConfigurationService tenantConfigurationService) {
        this.keyStoreFactory = keyStoreFactory;
        this.tenantConfigurationService = tenantConfigurationService;
        LOGGER.info("Initialized KeyStoreConfigByJavaKeyStore with factory pattern");
    }

    /**
     * Generate KeyStore for current tenant using factory pattern.
     * This method is called during request processing when tenant context is available.
     *
     * @return KeyStore for current tenant
     */
    public KeyStore generateKeyStore() {
        LOGGER.debug("## generateKeyStore - START using factory");
        KeyStore keyStore = keyStoreFactory.getKeyStoreForCurrentTenant();
        LOGGER.debug("## generateKeyStore - END");
        return keyStore;
    }

    /**
     * Generate RSA Key for current tenant using factory pattern.
     * This method is called during request processing when tenant context is available.
     *
     * @return RSAKey for current tenant
     */
    public RSAKey generateRsaKey() {
        LOGGER.debug("## generateRsaKey using factory");
        
        try {
            KeyPair keyPair = keyStoreFactory.getRsaKeyPairForCurrentTenant();
            
            // Get current tenant for key ID
            String tenantId = TenantContext.getCurrentTenant();
            String jwtKeyId = tenantConfigurationService.getTenantProperties().getKeyStore().get(TENANT_JWT_KEY_ID);
            
            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey(keyPair.getPrivate())
                    .keyID(tenantId + "-" + jwtKeyId)
                    .build();
                    
        } catch (Exception e) {
            LOGGER.error("Failed to generate RSA key using factory: ", e);
            throw new KeyGenerationException(e);
        }
    }
}