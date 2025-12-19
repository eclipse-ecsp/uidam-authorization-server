/*
 *
 *   ******************************************************************************
 *
 *    Copyright (c) 2023-24 Harman International
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *
 *    you may not use this file except in compliance with the License.
 *
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *    See the License for the specific language governing permissions and
 *
 *    limitations under the License.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    *******************************************************************************
 *
 */

package org.eclipse.ecsp.uidam.config;

import lombok.Getter;
import lombok.Setter;
import org.eclipse.ecsp.sql.multitenancy.TenantDatabaseProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration class to enable dynamic refresh of tenant database configuration map.
 * 
 * <p>This implementation uses a wrapper approach to work around the limitation that
 * the SQL-DAO library's tenant config map is not refresh-scoped by default.
 * 
 * <p>Strategy:
 * <ol>
 * <li>Create a separate RefreshableTenantConfig bean with @RefreshScope</li>
 * <li>This wrapper bean gets updated when /actuator/refresh is called</li>
 * <li>Manually sync the updated tenant properties to SQL-DAO's tenant config map</li>
 * <li>TenantAwareDataSource uses the updated properties from SQL-DAO bean</li>
 * </ol>
 * 
 * <p>This approach avoids using @Primary which might cause bean injection conflicts,
 * and instead maintains the original SQL-DAO bean while providing a refresh mechanism.
 *
 * @see org.eclipse.ecsp.sql.multitenancy.TenantDatabaseProperties
 */
@Configuration
public class TenantDatabaseConfigRefresh {

    private static final Logger LOGGER = LoggerFactory.getLogger(TenantDatabaseConfigRefresh.class);

    /**
     * Wrapper class for tenant database properties that supports refresh.
     * This mirrors the structure from sql-dao's TenantConfig but with RefreshScope support.
     */
    @Getter
    @Setter
    @ConfigurationProperties(prefix = "tenants")
    public static class RefreshableTenantConfig {
        /** Map of tenant IDs to their database properties. */
        private Map<String, TenantDatabaseProperties> profile = new HashMap<>();
    }

    /**
     * Creates a refresh-scoped wrapper bean for tenant database configuration.
     * 
     * <p>This bean will be destroyed and recreated when /actuator/refresh is called,
     * automatically loading the updated tenant configurations from the Config Server.
     *
     * @return RefreshableTenantConfig instance that refreshes on config changes
     */
    @Bean
    @RefreshScope
    public RefreshableTenantConfig refreshableTenantConfig() {
        LOGGER.debug("Creating/recreating refresh-scoped RefreshableTenantConfig bean");
        return new RefreshableTenantConfig();
    }

    /**
     * Synchronizes tenant properties from the refreshable wrapper to SQL-DAO's tenant config map.
     * 
     * <p>This method should be called after /actuator/refresh to update the SQL-DAO bean
     * with the latest tenant configurations from the refreshable wrapper bean.
     *
     * @param sqlDaoProperties the SQL-DAO tenant config map bean
     * @param refreshableConfig the refreshable wrapper bean with updated properties
     */
    public void syncTenantProperties(
            Map<String, TenantDatabaseProperties> sqlDaoProperties,
            RefreshableTenantConfig refreshableConfig) {
        
        Map<String, TenantDatabaseProperties> updatedProfile = refreshableConfig.getProfile();
        
        LOGGER.info("Syncing tenant properties from RefreshableTenantConfig to SQL-DAO tenant config map");
        LOGGER.info("Updated tenant count: {}, Tenant IDs: {}", 
                   updatedProfile.size(), updatedProfile.keySet());
        
        // Update the SQL-DAO map with new tenant properties
        sqlDaoProperties.clear();
        sqlDaoProperties.putAll(updatedProfile);
        
        LOGGER.info("Successfully synced tenant database properties to SQL-DAO bean");
    }
}
