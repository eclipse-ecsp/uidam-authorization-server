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

import org.eclipse.ecsp.uidam.util.ConfigurationPropertyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Early-stage processor that ensures all tenant configurations have complete properties
 * by creating missing properties from default tenant configuration.
 *
 * <p>This processor implements BeanFactoryPostProcessor to run before any bean initialization
 * and EnvironmentAware to access the Spring Environment early in the lifecycle.
 * It also implements Ordered with HIGHEST_PRECEDENCE to ensure it runs before other processors.
 */
@Component
public class TenantDefaultPropertiesProcessor implements BeanFactoryPostProcessor, EnvironmentAware, Ordered {

    private static final Logger LOGGER = LoggerFactory.getLogger(TenantDefaultPropertiesProcessor.class);
    
    private static final String TENANT_PREFIX = "tenants.profile.";
    private static final String DEFAULT_TENANT_PREFIX = "tenant.props.";
    private static final String DEFAULT_TENANT = "default";
    private static final String TENANT_IDS_PROPERTY = "tenant.ids";
    private static final String TENANT_MULTITENANT_ENABLED_PROPERTY = "tenant.multitenant.enabled";
    private static final String TENANT_DEFAULT_PROPERTY = "tenant.default";
    private static final String TENANT_CONFIG_VALIDATION_ENABLED = "tenant.config.validation.enabled";
    private static final String TENANT_DBNAME_VALIDATION_PROPERTY = "uidam.tenant.config.dbname.validation";
    private static final int MIN_LENGTH_FOR_MASKING = 8;
    private static final int MASK_PREFIX_LENGTH = 4;
    private static final int MASK_SUFFIX_LENGTH = 4;
    
    private Environment environment;
    private Map<String, String> defaultProperties;

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        LOGGER.info("Starting TenantDefaultPropertiesProcessor - checking and creating missing tenant properties");
        
        if (!(environment instanceof ConfigurableEnvironment)) {
            LOGGER.warn("Environment is not ConfigurableEnvironment, cannot process tenant properties");
            return;
        }
        
        ConfigurableEnvironment configurableEnvironment = (ConfigurableEnvironment) environment;
        
        // Load default tenant properties
        loadDefaultProperties(configurableEnvironment);
        
        // Determine tenant IDs to process
        String[] tenantIds = determineTenantIds();
        if (tenantIds == null) {
            return;
        }
        
        // First validate default tenant properties
        boolean defaultValidationPassed = validateTenantProperties(DEFAULT_TENANT, configurableEnvironment, true);
        
        if (!defaultValidationPassed) {
            LOGGER.error("Default tenant validation failed. Cannot proceed with tenant property generation.");
            return;
        }
        
        // Process tenants
        processTenants(tenantIds, configurableEnvironment);
    }
    
    /**
     * Determines which tenant IDs to process based on multitenancy configuration.
     *
     * @return array of tenant IDs, or null if no tenants to process
     */
    private String[] determineTenantIds() {
        boolean multitenancyEnabled = environment.getProperty(TENANT_MULTITENANT_ENABLED_PROPERTY, 
                                                               Boolean.class, false);
        
        if (multitenancyEnabled) {
            String tenantIdsStr = environment.getProperty(TENANT_IDS_PROPERTY);
            if (tenantIdsStr == null || tenantIdsStr.trim().isEmpty()) {
                LOGGER.info("Multitenancy is enabled but no tenant IDs configured, "
                    + "skipping tenant property validation");
                return null;
            }
            String[] tenantIds = tenantIdsStr.split(",");
            LOGGER.info("Multitenancy enabled. Processing {} tenants: {}", 
                tenantIds.length, tenantIdsStr);
            return tenantIds;
        } else {
            String defaultTenant = environment.getProperty(TENANT_DEFAULT_PROPERTY);
            if (defaultTenant == null || defaultTenant.trim().isEmpty()) {
                LOGGER.info("Multitenancy is disabled and no default tenant configured, "
                    + "skipping tenant property validation");
                return null;
            }
            LOGGER.info("Multitenancy disabled. Processing single tenant: {}", defaultTenant);
            return new String[]{defaultTenant};
        }
    }
    
    /**
     * Processes all tenants, validating and generating properties.
     *
     * @param tenantIds array of tenant IDs to process
     * @param configurableEnvironment the Spring environment
     */
    private void processTenants(String[] tenantIds, ConfigurableEnvironment configurableEnvironment) {
        Map<String, String> generatedProperties = new HashMap<>();
        List<String> failedTenants = new ArrayList<>();
        
        for (String tenantId : tenantIds) {
            String trimmedTenantId = tenantId.trim();
            if (!trimmedTenantId.isEmpty() && !DEFAULT_TENANT.equals(trimmedTenantId)) {
                boolean validationPassed = validateTenantProperties(trimmedTenantId, configurableEnvironment, false);
                
                if (validationPassed) {
                    processTenant(trimmedTenantId, configurableEnvironment, generatedProperties);
                    LOGGER.info("Tenant [{}] processing completed successfully", trimmedTenantId);
                } else {
                    failedTenants.add(trimmedTenantId);
                    LOGGER.error("Tenant [{}] validation failed. Skipping property generation.", 
                        trimmedTenantId);
                }
            }
        }
        
        // Remove failed tenants from tenant.ids if any
        if (!failedTenants.isEmpty()) {
            removeFailedTenantsFromEnvironment(configurableEnvironment, failedTenants);
        }
        
        // Add generated properties to environment
        if (!generatedProperties.isEmpty()) {
            addGeneratedPropertiesToEnvironment(configurableEnvironment, generatedProperties);
        }
    }
    
    /**
     * Adds generated properties to the environment.
     *
     * @param configurableEnvironment the Spring environment
     * @param generatedProperties map of generated properties
     */
    private void addGeneratedPropertiesToEnvironment(ConfigurableEnvironment configurableEnvironment,
                                                      Map<String, String> generatedProperties) {
        Map<String, Object> propertyMap = new HashMap<>(generatedProperties);
        MapPropertySource generatedPropertySource = new MapPropertySource(
            "generatedTenantProperties", propertyMap);
        configurableEnvironment.getPropertySources().addLast(generatedPropertySource);
        LOGGER.info("Added {} generated tenant properties to environment", generatedProperties.size());
    }
    
    /**
     * Loads all default tenant properties from the environment.
     */
    private void loadDefaultProperties(ConfigurableEnvironment environment) {
        defaultProperties = new HashMap<>();
        String defaultPrefix = DEFAULT_TENANT_PREFIX + DEFAULT_TENANT + ".";
        
        // Iterate through all property sources to find default tenant properties
        for (PropertySource<?> propertySource : environment.getPropertySources()) {
            if (propertySource instanceof org.springframework.core.env.EnumerablePropertySource) {
                org.springframework.core.env.EnumerablePropertySource<?> enumerablePropertySource = 
                    (org.springframework.core.env.EnumerablePropertySource<?>) propertySource;
                
                for (String propertyName : enumerablePropertySource.getPropertyNames()) {
                    if (propertyName.startsWith(defaultPrefix)) {
                        String suffix = propertyName.substring(defaultPrefix.length());
                        Object value = environment.getProperty(propertyName);
                        if (value != null) {
                            defaultProperties.put(suffix, value.toString());
                        }
                    }
                }
            }
        }
        
        LOGGER.info("Loaded {} default tenant properties", defaultProperties.size());
    }
    
    /**
     * Processes a single tenant to check and create missing properties.
     */
    private void processTenant(String tenantId, ConfigurableEnvironment environment, 
                               Map<String, String> generatedProperties) {
        LOGGER.info("Processing tenant: {}", tenantId);
        
        int createdCount = 0;
        String tenantPrefix = TENANT_PREFIX + tenantId + ".";
        
        // Check each default property and create if missing
        for (Map.Entry<String, String> defaultEntry : defaultProperties.entrySet()) {
            String propertySuffix = defaultEntry.getKey();
            String tenantPropertyName = tenantPrefix + propertySuffix;
            
            // Check if property exists for this tenant
            String existingValue = environment.getProperty(tenantPropertyName);
            
            if (existingValue == null) {
                // Property doesn't exist, create it from default
                String defaultValue = defaultEntry.getValue();
                String generatedValue = generateTenantValue(tenantId, propertySuffix, defaultValue, environment);
                
                generatedProperties.put(tenantPropertyName, generatedValue);
                createdCount++;
                
                LOGGER.debug("Created property: {} = {}", tenantPropertyName, 
                    isSensitiveProperty(propertySuffix) ? "****" : generatedValue);
            }
        }
        
        LOGGER.info("Created {} missing properties for tenant: {}", createdCount, tenantId);
    }
    
    /**
     * Generates a tenant-specific value from the default value.
     * Special handling for database properties (JDBC URL, credentials).
     */
    private String generateTenantValue(String tenantId, String propertySuffix, 
                                       String defaultValue, ConfigurableEnvironment environment) {
        // Special handling for JDBC URL - update database name with tenant ID
        if (propertySuffix.equals("jdbc-url")) {
            return generateTenantJdbcUrl(tenantId, defaultValue, environment);
        }
        
        // Special handling for tenant-id property
        if (propertySuffix.equals("tenant-id")) {
            return tenantId;
        }
        
        // Special handling for tenant-name property
        if (propertySuffix.equals("tenant-name")) {
            return tenantId;
        }
        
        // Special handling for alias property
        if (propertySuffix.equals("alias")) {
            return tenantId;
        }
        
        // Special handling for account-name
        if (propertySuffix.equals("account.account-name")) {
            return tenantId;
        }
        
        // For other properties, use the default value as-is
        return defaultValue;
    }
    
    /**
     * Generates tenant-specific JDBC URL.
     * Delegates to ConfigurationPropertyUtils utility class for consistent URL generation logic.
     */
    private String generateTenantJdbcUrl(String tenantId, String defaultJdbcUrl, 
                                         ConfigurableEnvironment environment) {
        String jdbcUrl = ConfigurationPropertyUtils.generateTenantJdbcUrl(tenantId, environment, defaultJdbcUrl);
        
        if (jdbcUrl == null) {
            LOGGER.warn("Could not generate JDBC URL for tenant {}, using default URL", tenantId);
            return defaultJdbcUrl;
        }
        
        return jdbcUrl;
    }
    
    /**
     * Checks if a property contains sensitive information that should not be logged.
     */
    private boolean isSensitiveProperty(String propertySuffix) {
        return propertySuffix.contains("password") 
               || propertySuffix.contains("secret") 
               || propertySuffix.contains("key")
               || propertySuffix.contains("salt");
    }
    
    /**
     * Refreshes tenant properties dynamically when tenants are added or removed.
     * This method should be called from ConfigRefreshListener when tenant.ids changes.
     * It processes new tenants and generates missing properties for them.
     *
     * @param newTenantIds comma-separated list of tenant IDs
     * @param configurableEnvironment the Spring environment
     * @return list of tenant IDs that failed validation and were removed
     */
    public List<String> refreshTenantProperties(String newTenantIds, ConfigurableEnvironment configurableEnvironment) {
        LOGGER.info("Refreshing tenant properties for tenants: {}", newTenantIds);
        
        List<String> failedTenants = new ArrayList<>();
        
        if (newTenantIds == null || newTenantIds.trim().isEmpty()) {
            LOGGER.warn("No tenant IDs provided for property refresh");
            return failedTenants;
        }
        
        // Reload default properties to ensure we have the latest
        loadDefaultProperties(configurableEnvironment);
        
        // First validate default tenant properties
        boolean defaultValidationPassed = validateTenantProperties(DEFAULT_TENANT, configurableEnvironment, true);
        
        if (!defaultValidationPassed) {
            LOGGER.error("Default tenant validation failed during refresh. "
                + "Cannot proceed with tenant property generation.");
            return failedTenants;
        }
        
        // Process each tenant
        String[] tenantIds = newTenantIds.split(",");
        Map<String, String> generatedProperties = new HashMap<>();
        List<String> successfulTenants = new ArrayList<>();
        
        for (String tenantId : tenantIds) {
            String trimmedTenantId = tenantId.trim();
            if (!trimmedTenantId.isEmpty() && !DEFAULT_TENANT.equals(trimmedTenantId)) {
                // Validate tenant properties before processing
                boolean validationPassed = validateTenantProperties(trimmedTenantId, configurableEnvironment, false);
                
                if (validationPassed) {
                    processTenant(trimmedTenantId, configurableEnvironment, generatedProperties);
                    successfulTenants.add(trimmedTenantId);
                    LOGGER.info("Tenant [{}] refresh processing completed successfully", trimmedTenantId);
                } else {
                    failedTenants.add(trimmedTenantId);
                    LOGGER.error("Tenant [{}] validation failed during refresh. "
                        + "Skipping property generation for this tenant.", trimmedTenantId);
                }
            }
        }
        
        // Remove failed tenants from tenant.ids if any
        if (!failedTenants.isEmpty()) {
            removeFailedTenantsFromEnvironment(configurableEnvironment, failedTenants);
        }
        
        // Add generated properties to environment if any were created
        if (!generatedProperties.isEmpty()) {
            // Remove old generated property source if it exists
            if (configurableEnvironment.getPropertySources().contains("generatedTenantProperties")) {
                configurableEnvironment.getPropertySources().remove("generatedTenantProperties");
            }
            
            Map<String, Object> propertyMap = new HashMap<>(generatedProperties);
            MapPropertySource generatedPropertySource = new MapPropertySource(
                "generatedTenantProperties", propertyMap);
            configurableEnvironment.getPropertySources().addLast(generatedPropertySource);
            LOGGER.info("Refreshed {} tenant properties in environment", generatedProperties.size());
        } else {
            LOGGER.info("No new properties needed for tenant refresh");
        }
        
        return failedTenants;
    }
    
    /**
     * Validates required tenant properties.
     * Checks if validation is enabled before performing validation.
     * Database name validation runs independently of tenant.config.validation.enabled.
     *
     * @param tenantId the tenant ID
     * @param environment the Spring environment
     * @param isDefaultTenant true if validating default tenant properties (uses tenant.props prefix),
     *                        false if validating actual tenant properties (uses tenants.profile prefix)
     * @return true if validation passed or is disabled, false if validation failed
     */
    private boolean validateTenantProperties(String tenantId, ConfigurableEnvironment environment, 
                                            boolean isDefaultTenant) {
        boolean allValidationsPassed = true;
        
        // Check if standard validation is enabled
        boolean validationEnabled = environment.getProperty(TENANT_CONFIG_VALIDATION_ENABLED, 
                                                            Boolean.class, true);
        
        if (validationEnabled) {
            LOGGER.info("Validating properties for tenant: {} (isDefault: {})", tenantId, isDefaultTenant);
            
            List<String> missingProperties = new ArrayList<>();
            // Use appropriate prefix based on whether this is the default tenant or actual tenant
            String tenantPrefix = isDefaultTenant 
                ? (DEFAULT_TENANT_PREFIX + tenantId + ".") 
                : (TENANT_PREFIX + tenantId + ".");
            
            // Validate database properties
            validateProperty(environment, tenantPrefix + "jdbc-url", "jdbc-url", missingProperties);
            validateProperty(environment, tenantPrefix + "user-name", "user-name", missingProperties);
            validateProperty(environment, tenantPrefix + "password", "password", missingProperties);
            
            // Validate keystore properties
            validateProperty(environment, tenantPrefix + "key-store.key-store-jks-encoded-content", 
                            "key-store.key-store-jks-encoded-content", missingProperties);
            validateProperty(environment, tenantPrefix + "key-store.key-store-password", 
                            "key-store.key-store-password", missingProperties);
            validateProperty(environment, tenantPrefix + "key-store.key-alias", 
                            "key-store.key-alias", missingProperties);
            validateProperty(environment, tenantPrefix + "key-store.key-type", 
                            "key-store.key-type", missingProperties);
            
            // Validate captcha properties
            validateProperty(environment, tenantPrefix + "captcha.recaptcha-key-site", 
                            "captcha.recaptcha-key-site", missingProperties);
            validateProperty(environment, tenantPrefix + "captcha.recaptcha-key-secret", 
                            "captcha.recaptcha-key-secret", missingProperties);
            
            // Log validation results
            if (!missingProperties.isEmpty()) {
                LOGGER.error("Tenant [{}] - Standard validation FAILED. "
                    + "Missing or empty required properties: {}", 
                    tenantId, String.join(", ", missingProperties));
                allValidationsPassed = false;
            } else {
                LOGGER.info("Tenant [{}] - Standard validation PASSED. "
                    + "All required properties are configured.", tenantId);
            }
            
            // Log property values (masked for sensitive data)
            logTenantPropertyValues(tenantId, environment, isDefaultTenant);
        } else {
            LOGGER.debug("Tenant property validation is disabled. "
                + "Skipping standard validation for tenant: {}", tenantId);
        }
        
        // Database name validation - runs INDEPENDENTLY of tenant.config.validation.enabled
        // Skip DB name validation for default tenant
        if (isDefaultTenant || DEFAULT_TENANT.equalsIgnoreCase(tenantId)) {
            return allValidationsPassed;
        }
        boolean dbNameValidationPassed = validateDatabaseName(tenantId, environment, isDefaultTenant);
        if (!dbNameValidationPassed) {
            allValidationsPassed = false;
        }
        
        return allValidationsPassed;
    }
    
    /**
     * Validates the database name in the JDBC URL against the tenant ID.
     * This validation runs independently of tenant.config.validation.enabled.
     *
     * @param tenantId the tenant ID
     * @param environment the Spring environment
     * @param isDefaultTenant true if validating default tenant properties, false for actual tenant
     * @return true if validation passed, false otherwise
     */
    private boolean validateDatabaseName(String tenantId, ConfigurableEnvironment environment, 
                                        boolean isDefaultTenant) {
        // Get the validation mode
        String validationModeStr = environment.getProperty(TENANT_DBNAME_VALIDATION_PROPERTY, "EQUAL");
        DatabaseNameValidationMode validationMode = DatabaseNameValidationMode.fromString(validationModeStr);
        
        LOGGER.info("Database name validation mode for tenant [{}]: {}", tenantId, validationMode);
        
        if (validationMode == DatabaseNameValidationMode.NONE) {
            LOGGER.info("Database name validation is disabled (mode: NONE) for tenant: {}", tenantId);
            return true;
        }
        
        // Get the JDBC URL for the tenant using appropriate prefix
        String tenantPrefix = isDefaultTenant 
            ? (DEFAULT_TENANT_PREFIX + tenantId + ".") 
            : (TENANT_PREFIX + tenantId + ".");
        String jdbcUrl = environment.getProperty(tenantPrefix + "jdbc-url");
        
        if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
            LOGGER.info("JDBC URL not found for tenant [{}]. skipping database name validation.", tenantId);
            return true;
        }
        
        // Perform the validation
        boolean isValid = TenantDatabaseNameValidator.validateDatabaseName(tenantId, jdbcUrl, validationMode);
        
        if (!isValid) {
            LOGGER.error("Tenant [{}] - Database name validation FAILED. JDBC URL: {}, Validation Mode: {}", 
                        tenantId, jdbcUrl, validationMode);
        }
        
        return isValid;
    }
    
    /**
     * Validates a single property by checking if it exists and is not empty.
     *
     * @param environment the Spring environment
     * @param propertyName the full property name
     * @param propertyDisplayName the display name for logging
     * @param missingProperties list to add missing property names to
     */
    private void validateProperty(ConfigurableEnvironment environment, String propertyName, 
                                   String propertyDisplayName, List<String> missingProperties) {
        String value = environment.getProperty(propertyName);
        if (isNullOrEmpty(value)) {
            missingProperties.add(propertyDisplayName);
        }
    }
    
    /**
     * Logs tenant property values with sensitive data masked.
     *
     * @param tenantId the tenant ID
     * @param environment the Spring environment
     * @param isDefaultTenant true if logging default tenant properties, false for actual tenant
     */
    private void logTenantPropertyValues(String tenantId, ConfigurableEnvironment environment, 
                                        boolean isDefaultTenant) {
        // Use appropriate prefix based on whether this is the default tenant or actual tenant
        String tenantPrefix = isDefaultTenant 
            ? (DEFAULT_TENANT_PREFIX + tenantId + ".") 
            : (TENANT_PREFIX + tenantId + ".");
        
        // Log database properties
        String jdbcUrl = environment.getProperty(tenantPrefix + "jdbc-url");
        String username = environment.getProperty(tenantPrefix + "user-name");
        String password = environment.getProperty(tenantPrefix + "password");
        
        LOGGER.info("Tenant [{}] - Database properties - JDBC URL: {}, Username: {}, Password: {}", 
                    tenantId, 
                    jdbcUrl != null ? jdbcUrl : "NOT_SET", 
                    username != null ? username : "NOT_SET", 
                    password != null && !password.isEmpty() ? "****" : "NOT_SET");
        
        // Log keystore properties
        String keyAlias = environment.getProperty(tenantPrefix + "key-store.key-alias");
        String keyType = environment.getProperty(tenantPrefix + "key-store.key-type");
        String keyStorePassword = environment.getProperty(tenantPrefix + "key-store.key-store-password");
        String keyStoreContent = environment.getProperty(tenantPrefix + "key-store.key-store-jks-encoded-content");
        
        LOGGER.info("Tenant [{}] - KeyStore properties - Alias: {}, Type: {}, Password: {}, Content: {}", 
                    tenantId,
                    keyAlias != null ? keyAlias : "NOT_SET",
                    keyType != null ? keyType : "NOT_SET",
                    keyStorePassword != null && !keyStorePassword.isEmpty() ? "****" : "NOT_SET",
                    !isNullOrEmpty(keyStoreContent) ? "SET" : "NOT_SET");
        
        // Log captcha properties
        String siteKey = environment.getProperty(tenantPrefix + "captcha.recaptcha-key-site");
        String secretKey = environment.getProperty(tenantPrefix + "captcha.recaptcha-key-secret");
        
        LOGGER.info("Tenant [{}] - Captcha properties - Site Key: {}, Secret Key: {}", 
                    tenantId,
                    siteKey != null ? maskSensitiveValue(siteKey) : "NOT_SET",
                    secretKey != null && !secretKey.isEmpty() ? "****" : "NOT_SET");
    }
    
    /**
     * Checks if a string is null or empty.
     *
     * @param value the string to check
     * @return true if null or empty, false otherwise
     */
    private boolean isNullOrEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }
    
    /**
     * Masks sensitive values for logging, showing only first and last few characters.
     *
     * @param value the value to mask
     * @return masked value
     */
    private String maskSensitiveValue(String value) {
        if (value == null || value.length() <= MIN_LENGTH_FOR_MASKING) {
            return "****";
        }
        return value.substring(0, MASK_PREFIX_LENGTH) + "****" 
            + value.substring(value.length() - MASK_SUFFIX_LENGTH);
    }
    
    /**
     * Removes failed tenants from the tenant.ids property in the environment.
     * Updates both the system property and the environment property.
     * Only performs removal if multitenancy is enabled.
     *
     * @param environment the Spring environment
     * @param failedTenants list of tenant IDs that failed validation
     */
    private void removeFailedTenantsFromEnvironment(ConfigurableEnvironment environment, List<String> failedTenants) {
        if (failedTenants == null || failedTenants.isEmpty()) {
            return;
        }
        
        // Check if multitenancy is enabled
        boolean multitenancyEnabled = environment.getProperty(TENANT_MULTITENANT_ENABLED_PROPERTY, 
                                                               Boolean.class, false);
        
        if (!multitenancyEnabled) {
            LOGGER.info("Multitenancy is not enabled, skipping removal of failed tenants: {}", 
                       String.join(", ", failedTenants));
            return;
        }
        
        // Get current tenant IDs
        String currentTenantIds = environment.getProperty(TENANT_IDS_PROPERTY, "");
        
        if (currentTenantIds == null || currentTenantIds.trim().isEmpty()) {
            return;
        }
        
        // Split and filter out failed tenants
        String[] tenantIdArray = currentTenantIds.split(",");
        List<String> remainingTenants = new ArrayList<>();
        
        for (String tenantId : tenantIdArray) {
            String trimmedTenantId = tenantId.trim();
            if (!trimmedTenantId.isEmpty() && !failedTenants.contains(trimmedTenantId)) {
                remainingTenants.add(trimmedTenantId);
            }
        }
        
        // Create updated tenant IDs string
        String updatedTenantIds = String.join(",", remainingTenants);
        
        // Update system property
        System.setProperty("multi.tenant.ids", updatedTenantIds);
        
        // Add updated property to environment
        Map<String, Object> propertyMap = new HashMap<>();
        propertyMap.put(TENANT_IDS_PROPERTY, updatedTenantIds);
        MapPropertySource updatedPropertySource = new MapPropertySource(
            "failedTenantRemovalProperties", propertyMap);
        environment.getPropertySources().addFirst(updatedPropertySource);
        
        LOGGER.error("Removed {} failed tenant(s) from tenant.ids: {}. Updated tenant.ids: {}", 
                    failedTenants.size(), 
                    String.join(", ", failedTenants),
                    updatedTenantIds.isEmpty() ? "EMPTY" : updatedTenantIds);
    }
}
