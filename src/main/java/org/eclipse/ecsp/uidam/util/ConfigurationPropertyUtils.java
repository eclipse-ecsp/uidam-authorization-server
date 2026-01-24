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

package org.eclipse.ecsp.uidam.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for configuration property operations.
 * This class provides common utilities for working with application configuration properties,
 * including tenant-specific property generation, property resolution, and URL manipulation.
 */
public final class ConfigurationPropertyUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigurationPropertyUtils.class);
    
    private static final String TENANT_PREFIX = "tenants.profile.";
    private static final String JDBC_URL_SUFFIX = ".jdbc-url";
    private static final String POSTGRES_JDBC_URL_PROPERTY = "postgres.jdbc.url";
    private static final int JDBC_URL_GROUP_HOST_PORT = 1;
    private static final int JDBC_URL_GROUP_PARAMS = 3;
    private static final int NOT_FOUND = -1;
    
    // Private constructor to prevent instantiation
    private ConfigurationPropertyUtils() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }
    
    /**
     * Generates a tenant-specific JDBC URL for PostgreSQL database.
     * The method follows this priority:
     * 1. Checks for tenant-specific environment variable (e.g., TENANT1_POSTGRES_DATASOURCE)
     * 2. Checks for tenant-specific property (tenants.profile.{tenantId}.jdbc-url)
     * 3. Generates from global postgres.jdbc.url by replacing database name with tenantId
     * 4. Generates from default/template JDBC URL using regex pattern matching
     *
     * @param tenantId the tenant identifier
     * @param environment Spring Environment for property resolution
     * @param defaultJdbcUrl optional default/template JDBC URL to use if specific URLs not found
     * @return tenant-specific JDBC URL, or null if generation fails
     */
    public static String generateTenantJdbcUrl(String tenantId, Environment environment, 
                                                String defaultJdbcUrl) {
        if (tenantId == null || tenantId.trim().isEmpty()) {
            LOGGER.error("Tenant ID cannot be null or empty");
            return null;
        }
        
        // Step 1: Try tenant-specific environment variable
        String envVarUrl = getTenantJdbcUrlFromEnvVar(tenantId, environment);
        if (envVarUrl != null) {
            return envVarUrl;
        }
        
        // Step 2: Try tenant-specific property
        String propertyUrl = getTenantJdbcUrlFromProperty(tenantId, environment);
        if (propertyUrl != null) {
            return propertyUrl;
        }
        
        // Step 3: Try generating from default/template URL using regex
        if (defaultJdbcUrl != null && !defaultJdbcUrl.isEmpty()) {
            String generatedUrl = generateFromTemplateUrl(tenantId, defaultJdbcUrl);
            if (generatedUrl != null) {
                return generatedUrl;
            }
        }
        
        LOGGER.warn("Could not generate JDBC URL for tenant: {}", tenantId);
        return null;
    }
    
    /**
     * Checks for tenant-specific JDBC URL in environment variable.
     * Expected format: {TENANT_ID}_POSTGRES_DATASOURCE
     *
     * @param tenantId the tenant identifier
     * @param environment Spring Environment for property resolution
     * @return JDBC URL from environment variable, or null if not found or invalid
     */
    private static String getTenantJdbcUrlFromEnvVar(String tenantId, Environment environment) {
        String tenantUpperCase = tenantId.toUpperCase().replace("-", "_");
        String tenantJdbcEnvVar = tenantUpperCase + "_POSTGRES_DATASOURCE";
        String envValue = environment.getProperty(tenantJdbcEnvVar);
        
        if (envValue != null && !envValue.isEmpty() && !envValue.equals("ChangeMe")) {
            LOGGER.info("Using tenant-specific JDBC URL from environment variable {} for tenant: {}", 
                tenantJdbcEnvVar, tenantId);
            return envValue;
        }
        return null;
    }
    
    /**
     * Checks for tenant-specific JDBC URL in application properties.
     * Expected property: tenants.profile.{tenantId}.jdbc-url
     *
     * @param tenantId the tenant identifier
     * @param environment Spring Environment for property resolution
     * @return JDBC URL from property, or null if not found or invalid
     */
    private static String getTenantJdbcUrlFromProperty(String tenantId, Environment environment) {
        String propertyName = TENANT_PREFIX + tenantId + JDBC_URL_SUFFIX;
        String propertyValue = environment.getProperty(propertyName);
        
        if (propertyValue != null && !propertyValue.isEmpty() && !propertyValue.equals("ChangeMe")) {
            LOGGER.info("Using tenant-specific JDBC URL from property {} for tenant: {}", 
                propertyName, tenantId);
            return propertyValue;
        }
        return null;
    }
    
    /**
     * Generates tenant JDBC URL from global postgres.jdbc.url by replacing database name.
     * This method uses a simple approach: finds the last '/' and replaces everything after it
     * with the tenant ID, preserving query parameters if present.
     *
     * <p>Expected format: jdbc:postgresql://host:port/database[?params]
     *
     * @param tenantId the tenant identifier
     * @param globalJdbcUrl the global JDBC URL
     * @return generated JDBC URL, or null if parsing fails
     */
    private static String generateFromGlobalJdbcUrl(String tenantId, String globalJdbcUrl) {
        try {
            // Find the last slash which separates host:port from database
            int lastSlashIndex = globalJdbcUrl.lastIndexOf('/');
            if (lastSlashIndex == NOT_FOUND) {
                LOGGER.warn("Invalid JDBC URL format (no '/' found): {}", globalJdbcUrl);
                return null;
            }
            
            // Check if there are query parameters
            String afterSlash = globalJdbcUrl.substring(lastSlashIndex + 1);
            int questionMarkIndex = afterSlash.indexOf('?');
            
            String baseUrl = globalJdbcUrl.substring(0, lastSlashIndex + 1);
            String params = "";
            
            if (questionMarkIndex != NOT_FOUND) {
                params = afterSlash.substring(questionMarkIndex);
            }
            
            String tenantJdbcUrl = baseUrl + tenantId + params;
            LOGGER.debug("Generated JDBC URL from global URL for tenant {}: {}", tenantId, tenantJdbcUrl);
            return tenantJdbcUrl;
            
        } catch (Exception e) {
            LOGGER.error("Error generating JDBC URL from global URL for tenant {}: {}", 
                tenantId, e.getMessage());
            return null;
        }
    }
    
    /**
     * Generates tenant JDBC URL from a template/default URL using regex pattern matching.
     * This method is more sophisticated and can handle complex URL patterns.
     *
     * <p>Expected pattern: jdbc:postgresql://host:port/database[?params]
     *
     * @param tenantId the tenant identifier
     * @param templateUrl the template JDBC URL
     * @return generated JDBC URL, or null if parsing fails
     */
    private static String generateFromTemplateUrl(String tenantId, String templateUrl) {
        try {
            // Pattern: jdbc:postgresql://host:port/database?params
            Pattern pattern = Pattern.compile("jdbc:postgresql://([^/]+)/(\\w+)(\\?.*)?");
            Matcher matcher = pattern.matcher(templateUrl);
            
            if (matcher.find()) {
                String hostAndPort = matcher.group(JDBC_URL_GROUP_HOST_PORT);
                String params = matcher.group(JDBC_URL_GROUP_PARAMS) != null 
                    ? matcher.group(JDBC_URL_GROUP_PARAMS) : "";
                
                String tenantJdbcUrl = "jdbc:postgresql://" + hostAndPort + "/" + tenantId + params;
                LOGGER.debug("Generated JDBC URL from template for tenant {}: {}", tenantId, tenantJdbcUrl);
                return tenantJdbcUrl;
            } else {
                LOGGER.warn("Could not parse JDBC URL pattern from template: {}", templateUrl);
                return null;
            }
            
        } catch (Exception e) {
            LOGGER.error("Error generating JDBC URL from template for tenant {}: {}", 
                tenantId, e.getMessage());
            return null;
        }
    }
    
    /**
     * Resolves a property value from the Spring Environment with a default fallback.
     * This is a convenience method for property resolution.
     *
     * @param environment Spring Environment for property resolution
     * @param key the property key
     * @param defaultValue the default value if property is not found
     * @return the property value or default
     */
    public static String getPropertyWithDefault(Environment environment, String key, String defaultValue) {
        return environment.getProperty(key, defaultValue);
    }
    
    /**
     * Resolves a boolean property value from the Spring Environment with a default fallback.
     *
     * @param environment Spring Environment for property resolution
     * @param key the property key
     * @param defaultValue the default value if property is not found
     * @return the property value or default
     */
    public static boolean getBooleanProperty(Environment environment, String key, boolean defaultValue) {
        return environment.getProperty(key, Boolean.class, defaultValue);
    }
    
    /**
     * Checks if a property value is defined and not a placeholder.
     * Useful for checking if a property has a real value vs. "ChangeMe" or empty.
     *
     * @param value the property value to check
     * @return true if the value is defined and not a placeholder
     */
    public static boolean isPropertyDefined(String value) {
        return value != null && !value.trim().isEmpty() && !value.equals("ChangeMe");
    }
    
    /**
     * Constructs a tenant-specific property key.
     * Example: constructTenantPropertyKey("tenant1", "jdbc-url") 
     *          returns "tenants.profile.tenant1.jdbc-url"
     *
     * @param tenantId the tenant identifier
     * @param propertySuffix the property suffix (e.g., "jdbc-url", "username")
     * @return the fully qualified tenant property key
     */
    public static String constructTenantPropertyKey(String tenantId, String propertySuffix) {
        return TENANT_PREFIX + tenantId + "." + propertySuffix;
    }
}
