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

import org.eclipse.ecsp.oauth2.server.core.config.LiquibaseConfig;
import org.eclipse.ecsp.sql.multitenancy.TenantAwareDataSource;
import org.eclipse.ecsp.sql.multitenancy.TenantDatabaseProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.environment.EnvironmentChangeEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Listener component that monitors configuration refresh events from Spring Cloud Config.
 * This listener is triggered when the /refresh actuator endpoint is called and captures
 * the list of property keys that have been changed in the configuration.
 *
 * <p>The changed properties are logged and stored in ConfigRefreshService for tracking
 * and potential auditing purposes.
 */
@Component
public class ConfigRefreshListener implements ApplicationListener<EnvironmentChangeEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigRefreshListener.class);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    // Properties to track for tenant management
    private static final String TENANT_IDS_KEY = "tenant.ids";
    private static final String DEFAULT_TENANT_KEY = "tenant.default-tenant-id";
    private static final String MULTITENANCY_ENABLED_KEY = "tenant.multitenant.enabled";
    
    // Constants for tenant property parsing
    private static final int TENANT_PROPERTY_MIN_PARTS = 3;
    private static final int TENANT_ID_PART_INDEX = 2;

    // Cache to store previous property values for tracked properties only
    private final Map<String, String> previousPropertyValues = new ConcurrentHashMap<>();

    @Autowired
    private ConfigurableEnvironment environment;

    @Autowired
    private TenantAwareDataSource tenantAwareDataSource;

    @Autowired
    private MultitenancySystemPropertyConfig multitenancySystemPropertyConfig;

    @Autowired
    private TenantDefaultPropertiesProcessor tenantDefaultPropertiesProcessor;

    @Autowired
    private Map<String, TenantDatabaseProperties> multiTenantDatabaseProperties;

    @Autowired
    private LiquibaseConfig liquibaseConfig;

    /**
     * Initializes the property cache with current values on application startup.
     * This ensures that the first refresh event will have accurate "old" values to compare against.
     */
    @PostConstruct
    public void initializePropertyCache() {
        // Initialize cache with current values of tracked properties
        String currentTenantIds = getCurrentValue(TENANT_IDS_KEY);
        if (currentTenantIds != null) {
            previousPropertyValues.put(TENANT_IDS_KEY, currentTenantIds);
            LOGGER.info("Initialized property cache: {} = {}", TENANT_IDS_KEY, currentTenantIds);
        }
        
        String currentDefaultTenant = getCurrentValue(DEFAULT_TENANT_KEY);
        if (currentDefaultTenant != null) {
            previousPropertyValues.put(DEFAULT_TENANT_KEY, currentDefaultTenant);
            LOGGER.info("Initialized property cache: {} = {}", DEFAULT_TENANT_KEY, currentDefaultTenant);
        }
        
        String currentMultitenancyEnabled = getCurrentValue(MULTITENANCY_ENABLED_KEY);
        if (currentMultitenancyEnabled != null) {
            previousPropertyValues.put(MULTITENANCY_ENABLED_KEY, currentMultitenancyEnabled);
            LOGGER.info("Initialized property cache: {} = {}", MULTITENANCY_ENABLED_KEY, currentMultitenancyEnabled);
        }
    }

    /**
     * Handles the EnvironmentChangeEvent triggered by the /refresh actuator endpoint.
     * This method is called automatically by Spring when configuration properties are refreshed.
     *
     * @param event the environment change event containing the set of changed property keys
     */
    @Override
    public void onApplicationEvent(EnvironmentChangeEvent event) {
        final Set<String> changedKeys = event.getKeys();
        String timestamp = LocalDateTime.now().format(DATE_FORMATTER);
        
        LOGGER.info("=================================================================");
        LOGGER.info("Configuration Refresh Event Detected at {}", timestamp);
        LOGGER.info("=================================================================");
        
        if (changedKeys == null || changedKeys.isEmpty()) {
            LOGGER.info("No configuration properties were changed.");
        } else {
            LOGGER.info("Total properties changed: {}", changedKeys.size());
            LOGGER.info("-----------------------------------------------------------------");
            
            // Check for tenant-specific changes first
            checkTenantChanges(changedKeys);
            
            int index = 1;
            for (String key : changedKeys) {
                String oldValue = getPreviousValue(key);
                String newValue = getCurrentValue(key);
                
                // Log the change with masking for sensitive properties
                if (isSensitiveProperty(key)) {
                    LOGGER.info("{}. Property: {} | Old Value: **** | New Value: ****", index++, key);
                } else {
                    LOGGER.info("{}. Property: {} | Old Value: {} | New Value: {}", 
                               index++, key, 
                               oldValue != null ? oldValue : "NOT_SET", 
                               newValue != null ? newValue : "NOT_SET");
                }
                
                // Update the cache only for tracked tenant properties
                if (isTrackedProperty(key) && newValue != null) {
                    previousPropertyValues.put(key, newValue);
                }
            }
            
            LOGGER.info("-----------------------------------------------------------------");
        }
        
        LOGGER.info("=================================================================");
    }
    
    /**
     * Checks for tenant-specific configuration changes and logs detailed information.
     *
     * @param changedKeys the set of changed property keys
     */
    private void checkTenantChanges(Set<String> changedKeys) {
        if (changedKeys.contains(TENANT_IDS_KEY)) {
            // When tenant.ids changes, handle additions, removals, and updates all together
            checkAndProcessTenantIdsChanges(changedKeys);
        } else {
            // When tenant.ids doesn't change but tenant properties do, check for updates only
            checkAndProcessTenantPropertyUpdates(changedKeys);
        }
        
        if (changedKeys.contains(MULTITENANCY_ENABLED_KEY)) {
            checkMultitenancyToggle();
        }
        
        if (changedKeys.contains(DEFAULT_TENANT_KEY)) {
            checkDefaultTenantChange();
        }
    }
    
    /**
     * Checks for changes in tenant.ids property and logs added/removed/updated tenants.
     * Iterates through each added/removed/updated tenant individually for custom processing.
     *
     * @param changedKeys the set of all changed property keys
     */
    private void checkAndProcessTenantIdsChanges(Set<String> changedKeys) {
        String oldTenantIds = previousPropertyValues.get(TENANT_IDS_KEY);
        String newTenantIds = getCurrentValue(TENANT_IDS_KEY);
        
        if (oldTenantIds == null || newTenantIds == null) {
            return;
        }
        
        Set<String> oldTenants = parseTenantIds(oldTenantIds);
        Set<String> newTenants = parseTenantIds(newTenantIds);
        
        // Get list of added tenants
        Set<String> addedTenants = new HashSet<>(newTenants);
        addedTenants.removeAll(oldTenants);
        
        // Get list of removed tenants
        Set<String> removedTenants = new HashSet<>(oldTenants);
        removedTenants.removeAll(newTenants);
        
        // Get list of existing tenants (common to both old and new)
        Set<String> existingTenants = new HashSet<>(oldTenants);
        existingTenants.retainAll(newTenants);

        if (!addedTenants.isEmpty() || !removedTenants.isEmpty()) {
            // Refresh system properties and tenant default properties after all tenant changes
            refreshTenantConfiguration(newTenantIds);
        }
        
        // Process each added tenant
        if (!addedTenants.isEmpty()) {
            LOGGER.warn(">>> TENANTS ADDED: {} - Previous tenants: [{}], Current tenants: [{}]",
                       String.join(", ", addedTenants), 
                       String.join(", ", oldTenants),
                       String.join(", ", newTenants));
            
            for (String tenantId : addedTenants) {
                LOGGER.info("Processing added tenant: {}", tenantId);
                processTenantAddition(tenantId);
            }
        }
        
        // Process each removed tenant
        if (!removedTenants.isEmpty()) {
            LOGGER.warn(">>> TENANTS REMOVED: {} - Previous tenants: [{}], Current tenants: [{}]",
                       String.join(", ", removedTenants),
                       String.join(", ", oldTenants),
                       String.join(", ", newTenants));
            
            for (String tenantId : removedTenants) {
                LOGGER.info("Processing removed tenant: {}", tenantId);
                processTenantRemoval(tenantId);
            }
        }
        
        // Check which existing tenants have property changes and process them
        final Set<String> updatedTenants = getUpdatedTenants(existingTenants, changedKeys);
        if (!updatedTenants.isEmpty()) {
            LOGGER.warn(">>> TENANTS UPDATED: {} tenant(s) have configuration changes: [{}]",
                       updatedTenants.size(),
                       String.join(", ", updatedTenants));
            
            for (String tenantId : updatedTenants) {
                LOGGER.info("Processing updated tenant: {}", tenantId);
                processTenantUpdate(tenantId, changedKeys);
            }
        }
        
    }
    
    /**
     * Identifies which existing tenants have property changes.
     * Checks if any tenant-specific properties have changed for tenants in the given set.
     *
     * @param existingTenants the set of tenants that exist in both old and new tenant lists
     * @param changedKeys the set of all changed property keys
     * @return Set of tenant IDs that have property changes
     */
    private Set<String> getUpdatedTenants(Set<String> existingTenants, Set<String> changedKeys) {
        Set<String> updatedTenants = new HashSet<>();
        
        // Check if any tenant-specific properties have changed
        for (String key : changedKeys) {
            if (key.startsWith("tenants.profile.")) {
                // Extract tenant ID from property key
                // Format: tenants.profile.{tenantId}.{property}
                String[] parts = key.split("\\.");
                if (parts.length >= TENANT_PROPERTY_MIN_PARTS) {
                    String tenantId = parts[TENANT_ID_PART_INDEX];
                    // Only include if this tenant exists in the existing tenants set
                    if (existingTenants.contains(tenantId)) {
                        updatedTenants.add(tenantId);
                    }
                }
            }
        }
        
        return updatedTenants;
    }
    
    /**
     * Placeholder method for processing tenant addition.
     * Implement custom logic here for handling new tenants.
     *
     * @param tenantId the ID of the tenant that was added
     */
    private void processTenantAddition(String tenantId) {
        LOGGER.info("Processing tenant addition for: {}", tenantId);
        
        try {
            // Build TenantDatabaseProperties from current environment properties
            TenantDatabaseProperties tenantDbProps = buildTenantDatabaseProperties(tenantId);
            
            if (tenantDbProps == null) {
                LOGGER.error("Failed to build database properties for tenant: {}. Cannot add tenant.", tenantId);
                return;
            }
            
            
            // Add tenant data source - SQL-DAO will read from the updated bean
            LOGGER.info("Start of adding new tenant DataSource: {}", tenantId);
            tenantAwareDataSource.addOrUpdateTenantDataSource(tenantId, tenantDbProps);
            LOGGER.info("Successfully added tenant data source for tenant: {}", tenantId);
            // Initialize tenant schema using Liquibase
            LOGGER.info("Initializing schema for tenant: {}", tenantId);
            liquibaseConfig.initializeTenantSchema(tenantId);
            LOGGER.info("Successfully initialized schema for tenant: {}", tenantId);
        } catch (Exception e) {
            LOGGER.error("Failed to add tenant data source for tenant: {}", tenantId, e);
        }
    }
    
    /**
     * Builds TenantDatabaseProperties from environment properties for a specific tenant.
     * Reads all tenants.profile.{tenantId}.* properties from the current environment.
     *
     * @param tenantId the tenant ID
     * @return TenantDatabaseProperties with values from environment, or null if required properties are missing
     */
    private TenantDatabaseProperties buildTenantDatabaseProperties(String tenantId) {
        String prefix = "tenants.profile." + tenantId + ".";
        
        // Read JDBC URL (required)
        String jdbcUrl = environment.getProperty(prefix + "jdbc-url");
        if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
            LOGGER.error("Missing required property: {}jdbc-url for tenant: {}", prefix, tenantId);
            return null;
        }
        
        // Read username (required)
        String userName = environment.getProperty(prefix + "user-name");
        if (userName == null || userName.trim().isEmpty()) {
            LOGGER.error("Missing required property: {}user-name for tenant: {}", prefix, tenantId);
            return null;
        }
        
        // Read password (required)
        String password = environment.getProperty(prefix + "password");
        if (password == null || password.trim().isEmpty()) {
            LOGGER.error("Missing required property: {}password for tenant: {}", prefix, tenantId);
            return null;
        }
        
        // Build TenantDatabaseProperties object
        TenantDatabaseProperties props = new TenantDatabaseProperties();
        props.setJdbcUrl(jdbcUrl);
        props.setUserName(userName);
        props.setPassword(password);
        
        // Read optional connection pool properties with defaults
        String minPoolSize = environment.getProperty(prefix + "min-pool-size", "10");
        String maxPoolSize = environment.getProperty(prefix + "max-pool-size", "30");
        String connectionTimeout = environment.getProperty(prefix + "connection-timeout-ms", "60000");
        String maxIdleTime = environment.getProperty(prefix + "max-idle-time", "0");
        
        try {
            props.setMinPoolSize(Integer.parseInt(minPoolSize));
            props.setMaxPoolSize(Integer.parseInt(maxPoolSize));
            props.setConnectionTimeoutMs(Integer.parseInt(connectionTimeout));
            props.setMaxIdleTime(Integer.parseInt(maxIdleTime));
        } catch (NumberFormatException e) {
            LOGGER.warn("Error parsing numeric connection pool properties for tenant: {}", tenantId, e);
        }
        
        // Read optional driver class name
        String driverClassName = environment.getProperty(prefix + "driver-class-name");
        if (driverClassName != null && !driverClassName.trim().isEmpty()) {
            props.setDriverClassName(driverClassName);
        }
        
        // Read optional pool name
        String poolName = environment.getProperty(prefix + "pool-name");
        if (poolName != null && !poolName.trim().isEmpty()) {
            props.setPoolName(poolName);
        }
        
        LOGGER.info("Built TenantDatabaseProperties for tenant: {} - JDBC URL: {}, Pool: {}-{}", 
                   tenantId, jdbcUrl, minPoolSize, maxPoolSize);
        
        return props;
    }
    
    /**
     * Placeholder method for processing tenant removal.
     * Implement custom logic here for handling removed tenants.
     *
     * @param tenantId the ID of the tenant that was removed
     */
    private void processTenantRemoval(String tenantId) {
        LOGGER.info("Processing tenant removal for: {}", tenantId);
        
        try {
            LOGGER.info("removing datasources for tenant: {}", tenantId);
            
            tenantAwareDataSource.removeTenantDataSource(tenantId);
            // Refresh tenant data sources to remove the deleted tenant
            LOGGER.info("Successfully refreshed tenant data sources after removing tenant: {}", tenantId);
        } catch (Exception e) {
            LOGGER.error("Failed to refresh tenant data sources for removed tenant: {}", tenantId, e);
        }
        
        // PLACEHOLDER: Add additional custom logic for tenant removal
        // Examples:
        // - Cleanup tenant-specific database schemas
        // - Clear tenant-specific cache entries
        // - Deregister tenant from external systems
        // - Archive tenant data
        // - Send notifications about tenant removal
    }
    
    /**
     * Refreshes tenant configuration after tenants are added or removed.
     * This method updates system properties and regenerates tenant default properties.
     *
     * @param newTenantIds the updated comma-separated list of tenant IDs
     */
    private void refreshTenantConfiguration(String newTenantIds) {
        LOGGER.info("Refreshing tenant configuration for updated tenant list: {}", newTenantIds);
        
        try {
            // Step 1: Refresh system properties (multi.tenant.ids)
            multitenancySystemPropertyConfig.refreshTenantSystemProperties();
            LOGGER.info("Successfully refreshed multitenancy system properties");
        } catch (Exception e) {
            LOGGER.error("Failed to refresh multitenancy system properties", e);
        }
        
        try {
            // Step 2: Refresh tenant default properties for new tenants
            tenantDefaultPropertiesProcessor.refreshTenantProperties(newTenantIds, environment);
            LOGGER.info("Successfully refreshed tenant default properties");
        } catch (Exception e) {
            LOGGER.error("Failed to refresh tenant default properties", e);
        }
    }
    
    /**
     * Checks for multitenancy enabled/disabled toggle.
     */
    private void checkMultitenancyToggle() {
        String oldValue = previousPropertyValues.get(MULTITENANCY_ENABLED_KEY);
        String newValue = getCurrentValue(MULTITENANCY_ENABLED_KEY);
        
        if (oldValue == null || newValue == null || oldValue.equals(newValue)) {
            return;
        }
        
        boolean wasEnabled = Boolean.parseBoolean(oldValue);
        boolean isEnabled = Boolean.parseBoolean(newValue);
        
        if (isEnabled && !wasEnabled) {
            LOGGER.warn(">>> MULTITENANCY ENABLED: Changed from '{}' to '{}'", oldValue, newValue);
        } else if (!isEnabled && wasEnabled) {
            LOGGER.warn(">>> MULTITENANCY DISABLED: Changed from '{}' to '{}'", oldValue, newValue);
        }
    }
    
    /**
     * Checks for default tenant ID changes.
     */
    private void checkDefaultTenantChange() {
        String oldDefaultTenant = previousPropertyValues.get(DEFAULT_TENANT_KEY);
        String newDefaultTenant = getCurrentValue(DEFAULT_TENANT_KEY);
        
        if (oldDefaultTenant != null && newDefaultTenant != null && !oldDefaultTenant.equals(newDefaultTenant)) {
            LOGGER.warn(">>> DEFAULT TENANT CHANGED: From '{}' to '{}'", oldDefaultTenant, newDefaultTenant);
        }
    }
    
    /**
     * Parses comma-separated tenant IDs into a Set.
     *
     * @param tenantIds comma-separated tenant IDs
     * @return Set of tenant IDs
     */
    private Set<String> parseTenantIds(String tenantIds) {
        if (tenantIds == null || tenantIds.trim().isEmpty()) {
            return new HashSet<>();
        }
        return Arrays.stream(tenantIds.split(","))
                .map(String::trim)
                .filter(id -> !id.isEmpty())
                .collect(Collectors.toSet());
    }
    
    /**
     * Checks if a property should be tracked for previous values.
     *
     * @param key the property key
     * @return true if the property should be tracked
     */
    private boolean isTrackedProperty(String key) {
        return TENANT_IDS_KEY.equals(key) 
            || DEFAULT_TENANT_KEY.equals(key) 
            || MULTITENANCY_ENABLED_KEY.equals(key);
    }

    /**
     * Gets the current value of a property from the environment.
     *
     * @param key the property key
     * @return the current property value or null if not found
     */
    private String getCurrentValue(String key) {
        try {
            return environment.getProperty(key);
        } catch (Exception e) {
            LOGGER.debug("Unable to retrieve current value for key: {}", key, e);
            return null;
        }
    }

    /**
     * Attempts to get the previous value of a property from cache.
     * The cache is populated after the first refresh event.
     *
     * @param key the property key
     * @return the previous property value from cache or null if not cached
     */
    private String getPreviousValue(String key) {
        return previousPropertyValues.get(key);
    }

    /**
     * Determines if a property key represents sensitive information that should be masked.
     *
     * @param key the property key
     * @return true if the property is sensitive, false otherwise
     */
    private boolean isSensitiveProperty(String key) {
        if (key == null) {
            return false;
        }
        
        String lowerKey = key.toLowerCase();
        return lowerKey.contains("password") 
            || lowerKey.contains("secret") 
            || lowerKey.contains("key") 
            || lowerKey.contains("token")
            || lowerKey.contains("credential")
            || lowerKey.contains("api-key")
            || lowerKey.contains("apikey");
    }
    
    /**
     * Checks for changes in tenant-specific properties for existing tenants.
     * Detects updates to properties like jdbc-url, username, password, pool settings, etc.
     *
     * @param changedKeys the set of changed property keys
     */
    private void checkAndProcessTenantPropertyUpdates(Set<String> changedKeys) {
        // Get current tenant IDs
        String currentTenantIds = getCurrentValue(TENANT_IDS_KEY);
        if (currentTenantIds == null || currentTenantIds.trim().isEmpty()) {
            return;
        }
        
        Set<String> currentTenants = parseTenantIds(currentTenantIds);
        Set<String> updatedTenants = new HashSet<>();
        
        // Check if any tenant-specific properties have changed
        for (String key : changedKeys) {
            if (key.startsWith("tenants.profile.")) {
                // Extract tenant ID from property key
                // Format: tenants.profile.{tenantId}.{property}
                String[] parts = key.split("\\.");
                if (parts.length >= TENANT_PROPERTY_MIN_PARTS) {
                    String tenantId = parts[TENANT_ID_PART_INDEX];
                    // Only process if this tenant currently exists
                    if (currentTenants.contains(tenantId)) {
                        updatedTenants.add(tenantId);
                    }
                }
            }
        }
        
        // Process each updated tenant
        if (!updatedTenants.isEmpty()) {
            LOGGER.warn(">>> TENANT PROPERTIES UPDATED: {} tenant(s) have configuration changes: [{}]",
                       updatedTenants.size(),
                       String.join(", ", updatedTenants));
            
            for (String tenantId : updatedTenants) {
                LOGGER.info("Processing property updates for tenant: {}", tenantId);
                processTenantUpdate(tenantId, changedKeys);
            }
        }
    }
    
    /**
     * Updates the tenant data source when database-related properties have changed.
     * This method rebuilds TenantDatabaseProperties and updates the data source connection pool.
     *
     * @param tenantId the ID of the tenant whose data source needs to be updated
     * @return true if the data source was successfully updated, false otherwise
     */
    private boolean updateTenantDataSource(String tenantId) {
        LOGGER.info("Database properties changed for tenant: {}. Updating data source...", tenantId);
        
        try {
            // Build updated TenantDatabaseProperties from current environment
            TenantDatabaseProperties updatedProps = buildTenantDatabaseProperties(tenantId);
            
            if (updatedProps == null) {
                LOGGER.error("Failed to build updated database properties for tenant: {}. "
                            + "Data source not updated.", tenantId);
                return false;
            }
            
            // Update tenant data source with new properties
            tenantAwareDataSource.addOrUpdateTenantDataSource(tenantId, updatedProps);
            LOGGER.info("Successfully updated data source for tenant: {}", tenantId);
            return true;
            
        } catch (Exception e) {
            LOGGER.error("Error updating data source for tenant: {}", tenantId, e);
            return false;
        }
    }
    
    /**
     * Checks if any database-related properties have changed for a tenant.
     * This includes connection properties, pool settings, and performance tuning parameters.
     *
     * @param changedTenantProperties the set of property names (without prefix) that changed for the tenant
     * @return true if any database-related property changed
     */
    private boolean isDatabasePropertyChanged(Set<String> changedTenantProperties) {
        // Database connection properties
        final Set<String> databaseProperties = Set.of(
            "jdbc-url",
            "user-name", 
            "password",
            "driver-class-name",
            // Connection pool properties
            "min-pool-size",
            "max-pool-size",
            "max-idle-time",
            "connection-timeout-ms",
            // Database schema and configuration
            "default-schema",
            // Performance tuning properties
            "cache-prep-stmts",
            "prep-stmt-cache-size",
            "prep-stmt-cache-sql-limit"
        );
        
        return changedTenantProperties.stream()
            .anyMatch(databaseProperties::contains);
    }
    
    /**
     * Processes tenant property updates for existing tenant configurations.
     * Handles database connection updates, pool configuration changes, and other tenant-specific properties.
     *
     * @param tenantId the ID of the tenant whose properties were updated
     * @param changedKeys all changed property keys to identify which specific properties changed
     */
    private void processTenantUpdate(String tenantId, Set<String> changedKeys) {
        LOGGER.info("Processing tenant property update for: {}", tenantId);
        
        // Identify which specific properties changed for this tenant
        String propertyPrefix = "tenants.profile." + tenantId + ".";
        Set<String> changedTenantProperties = changedKeys.stream()
            .filter(key -> key.startsWith(propertyPrefix))
            .map(key -> key.substring(propertyPrefix.length()))
            .collect(Collectors.toSet());
        
        if (!changedTenantProperties.isEmpty()) {
            LOGGER.info("Changed properties for tenant '{}': [{}]", 
                       tenantId, 
                       String.join(", ", changedTenantProperties));
        }
        
        try {
            // Check if any database-related properties changed
            if (isDatabasePropertyChanged(changedTenantProperties)) {
                // Update tenant data source with new configuration
                boolean updated = updateTenantDataSource(tenantId);
                
                if (updated) {
                    LOGGER.info("Tenant '{}' data source has been successfully updated with new configuration", 
                               tenantId);
                } else {
                    LOGGER.warn("Failed to update data source for tenant '{}'. "
                               + "Check logs for details.", tenantId);
                }
            } else {
                LOGGER.info("No database-related properties changed for tenant '{}'. "
                           + "Data source update not required.", tenantId);
            }
            
            // PLACEHOLDER: Add custom logic for other tenant property updates
            // Examples:
            // - If tenant-specific feature flags changed:
            //   * Refresh tenant configuration cache
            //   * Notify affected services
            //
            // - If keystore or security properties changed:
            //   * Reload certificates and keys
            //   * Update security context
            //
            // - Log audit trail of configuration changes
            // - Send notifications to administrators
            // - Update monitoring/alerting thresholds
            
        } catch (Exception e) {
            LOGGER.error("Error processing tenant property updates for tenant: {}", tenantId, e);
        }
    }
}
