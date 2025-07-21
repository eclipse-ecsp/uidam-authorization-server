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

import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MultiTenantProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * This service class is used to manage tenant configurations.
 * It provides multi-tenant support by managing configurations for multiple tenants.
 */
@Service
public class TenantConfigurationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TenantConfigurationService.class);
    
    private final MultiTenantProperties multiTenantProperties;

    /**
     * Constructor for TenantConfigurationService.
     * It initializes the service with multi-tenant properties.
     *
     * @param multiTenantProperties the multi-tenant properties configuration
     */
    public TenantConfigurationService(MultiTenantProperties multiTenantProperties) {
        this.multiTenantProperties = multiTenantProperties;
        
        // Add null safety for tenant properties
        if (multiTenantProperties.getTenants() != null) {
            LOGGER.info("TenantConfigurationService initialized with {} tenant(s)", 
                       multiTenantProperties.getTenants().size());
        } else {
            LOGGER.warn("TenantConfigurationService initialized with null tenant properties - check property loading");
        }
    }

    /**
     * This method retrieves the tenant properties for a given tenant ID.
     * It returns the tenant properties from the multi-tenant properties configuration.
     *
     * @param tenantId the ID of the tenant whose properties are to be retrieved
     * @return the tenant properties for the given tenant ID, or null if not found
     */
    public TenantProperties getTenantProperties(String tenantId) {
        // Add null safety check
        if (multiTenantProperties.getTenants() == null) {
            LOGGER.error("Multi-tenant properties not loaded - getTenants() returns null for tenant: {}", tenantId);
            return null;
        }
        
        TenantProperties properties = multiTenantProperties.getTenants().get(tenantId);
        if (properties == null) {
            LOGGER.warn("No properties found for tenant: {}", tenantId);
        }
        return properties;
    }
    
    /**
     * This method retrieves the tenant properties for the current tenant.
     * It uses the TenantContext to get the current tenant ID and returns the corresponding tenant properties.
     *
     * @return the tenant properties for the current tenant
     */
    public TenantProperties getTenantProperties() {
        String currentTenant = TenantContext.getCurrentTenant();
        LOGGER.debug("Getting properties for current tenant: {}", currentTenant);
        return getTenantProperties(currentTenant);
    }

    /**
     * Check if a tenant exists in the configuration.
     *
     * @param tenantId the tenant ID to check
     * @return true if the tenant exists, false otherwise
     */
    public boolean tenantExists(String tenantId) {
        // Add null safety check
        if (multiTenantProperties.getTenants() == null) {
            LOGGER.error("Multi-tenant properties not loaded - cannot check if tenant exists: {}", tenantId);
            return false;
        }
        return multiTenantProperties.getTenants().containsKey(tenantId);
    }

    /**
     * Get the default tenant properties.
     *
     * @return the default tenant properties
     */
    public TenantProperties getDefaultTenantProperties() {
        return multiTenantProperties.getDefaultTenant();
    }

    /**
     * Get the default tenant ID.
     *
     * @return the default tenant ID
     */
    public String getDefaultTenantId() {
        return multiTenantProperties.getDefaultTenantId();
    }
}
