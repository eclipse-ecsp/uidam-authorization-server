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

import org.eclipse.ecsp.sql.multitenancy.TenantDatabaseProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.annotation.PostConstruct;
import java.util.Map;
/**
 * Configuration class to bridge Spring application properties to System properties
 * for multitenancy support.
 * This is necessary because the sql-dao library reads multitenancy.enabled from
 * System properties, while the application defines it in application.properties.
 * 
 * <p>This class uses Environment.getProperty() to read current property values
 * when refreshTenantSystemProperties() is called, ensuring updated values are
 * always used after configuration refresh via /actuator/refresh endpoint.
 * 
 * <p>Note: @RefreshScope is intentionally NOT used to avoid bean initialization
 * order issues with early beans like TenantAwareDataSource that depend on
 * system properties being set during application startup.
 */

@Configuration
public class MultitenancySystemPropertyConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(MultitenancySystemPropertyConfig.class);

    @Autowired(required = false)
    private Map<String, TenantDatabaseProperties> multiTenantDbProperties;

    @Autowired
    private Environment environment;

    @Value("${multitenancy.enabled:true}")
    private boolean sqlMultitenancyEnabled;

    @Value("${tenant.multitenant.enabled:false}")
    private boolean tenantMultitenancyEnabled;

    @Value("${tenant.ids:}")
    private String tenantIds;

    @Value("${tenant.default:default}")
    private String defaultTenantId;

    /**
     * Initializes system properties for multitenancy configuration at startup.
     * This method is called after dependency injection to set system properties
     * that are read by the sql-dao library for tenant-based data source routing.
     * Sets multi.tenant.ids based on whether multitenancy is enabled or disabled.
     */
    @PostConstruct
    public void init() {
        // Set the system property so that sql-dao's TenantRoutingDataSource can read it
        System.setProperty("multitenancy.enabled", String.valueOf(sqlMultitenancyEnabled));
        
        // Perform initial setup of tenant properties
        refreshTenantSystemProperties();
    }
    
    /**
     * Refreshes tenant system properties dynamically.
     * This method can be called when tenant configuration changes (add/remove tenants).
     * It updates the multi.tenant.ids system property and logs database properties.
     * 
     * <p>Reads current values from Environment to get updated properties after /refresh.
     */
    public void refreshTenantSystemProperties() {
        // Read current values from Environment (updated after /refresh)
        boolean currentMultitenancyEnabled = environment.getProperty(
                "tenant.multitenant.enabled", Boolean.class, false);
        String currentTenantIds = environment.getProperty("tenant.ids", "");
        String currentDefaultTenantId = environment.getProperty("tenant.default", "default");
        
        if (currentMultitenancyEnabled) {
            System.setProperty("multi.tenant.ids", currentTenantIds);
            LOGGER.info("Tenant multitenancy is enabled. "
                    + "Setting multi.tenant.ids={}", currentTenantIds);
            
            // Log tenant database properties for each tenant
            logTenantDatabaseProperties(currentTenantIds);
        } else {
            System.setProperty("multi.tenant.ids", currentDefaultTenantId);
            LOGGER.info("Tenant multitenancy is disabled. "
                    + "Setting multi.tenant.ids={} for SQL-DAO", currentDefaultTenantId);
            
            // Log default tenant database properties
            logTenantDatabaseProperties(currentDefaultTenantId);
        }
    }
    
    /**
     * Logs database connection properties for the specified tenants.
     * Follows the pattern from sql-dao's PostgresDbConfig for fetching tenant properties.
     *
     * @param tenantIdsString comma-separated tenant IDs
     */
    private void logTenantDatabaseProperties(String tenantIdsString) {
        if (tenantIdsString == null || tenantIdsString.trim().isEmpty()) {
            LOGGER.warn("No tenant IDs provided for database property logging");
            return;
        }
        
        String[] tenantIdArray = tenantIdsString.split(",");
        for (String tenantId : tenantIdArray) {
            String trimmedTenantId = tenantId.trim();
            if (!trimmedTenantId.isEmpty()) {
                logSingleTenantProperties(trimmedTenantId);
            }
        }
    }
    
    /**
     * Logs database properties for a single tenant.
     * Fetches properties from TenantDatabaseProperties map following the pattern
     * used in sql-dao's PostgresDbConfig: multiTenantDbProperties.get(tenantId)
     *
     * @param tenantId the tenant ID
     */
    private void logSingleTenantProperties(String tenantId) {
        if (multiTenantDbProperties == null) {
            LOGGER.warn("TenantDatabaseProperties map is not available. "
                    + "Skipping tenant database property logging for tenant: {}", tenantId);
            return;
        }
        
        TenantDatabaseProperties tenantDbProps = multiTenantDbProperties.get(tenantId);
        
        if (tenantDbProps == null) {
            LOGGER.warn("No database properties found for tenant: {}", tenantId);
            return;
        }
        
        String jdbcUrl = tenantDbProps.getJdbcUrl();
        String username = tenantDbProps.getUserName();
        String password = tenantDbProps.getPassword();
        
        // Mask password for security
        String maskedPassword = (password != null && !password.isEmpty()) ? "****" : "NOT_SET";
        
        LOGGER.info("Tenant [{}] database properties - JDBC URL: {}, Username: {}, Password: {}", 
                    tenantId, 
                    jdbcUrl != null ? jdbcUrl : "NOT_SET", 
                    username != null ? username : "NOT_SET", 
                    maskedPassword);
    }
}
