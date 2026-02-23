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

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import jakarta.validation.Valid;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.validation.annotation.Validated;

import java.util.HashMap;
import java.util.Map;

/**
 * Multi-tenant properties configuration using prefix-based property binding.
 * Automatically binds properties with pattern: tenants.profile.{tenantId}.{property}
 * Compatible with Spring Config Server for dynamic property updates.
 */
@Getter
@Setter
@RefreshScope
@ConfigurationProperties(prefix = "tenants")
@Validated
public class MultiTenantProperties {
    
    /**
     * Map of tenant-specific configurations.
     * Spring automatically binds tenants.profile.{tenantId}.* properties to this map.
     * Key: tenant ID (e.g., "ecsp", "demo"), Value: tenant properties.
     */
    @Valid
    private Map<String, TenantProperties> profile = new HashMap<>();
    
    /**
     * Default tenant ID to use when tenant context is not set.
     */
    private String defaultTenantId = "ecsp";
    
    /**
     * Whether multi-tenancy is enabled.
     */
    private boolean multitenantEnabled = true;

    public boolean isMultitenantEnabled() {
        return multitenantEnabled;
    }

    public void setMultitenantEnabled(boolean multitenantEnabled) {
        this.multitenantEnabled = multitenantEnabled;
    }
    
    /**
     * Get tenant properties for a specific tenant ID.
     * Falls back to default tenant if specific tenant not found.
     *
     * @param tenantId the tenant ID
     * @return tenant properties for the specified tenant
     */
    public TenantProperties getTenantProperties(String tenantId) {
        return profile.get(tenantId);
    }
    
    /**
     * Get the default tenant configuration.
     *
     * @return default tenant properties
     */
    public TenantProperties getDefaultTenant() {
        return profile.getOrDefault(defaultTenantId, new TenantProperties());
    }
    
    /**
     * Check if tenant exists.
     *
     * @param tenantId the tenant ID to check
     * @return true if tenant exists
     */
    public boolean tenantExists(String tenantId) {
        return profile.containsKey(tenantId);
    }
    
    /**
     * Get all available tenant IDs.
     *
     * @return set of tenant IDs
     */
    public java.util.Set<String> getAvailableTenants() {
        return profile.keySet();
    }
}
