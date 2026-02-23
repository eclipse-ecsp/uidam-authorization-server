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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validator for checking database name in JDBC URL against tenant ID.
 * This validator runs independently of the tenant.config.validation.enabled property.
 */
public final class TenantDatabaseNameValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(TenantDatabaseNameValidator.class);
    
    // Pattern to extract database name from PostgreSQL JDBC URL
    // Format: jdbc:postgresql://host:port/database?params
    private static final Pattern JDBC_URL_PATTERN = Pattern.compile("jdbc:postgresql://[^/]+/(\\w+)(\\?.*)?");
    
    private static final int NOT_FOUND_INDEX = -1;
    
    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private TenantDatabaseNameValidator() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }
    
    /**
     * Validates the database name in the JDBC URL against the tenant ID
     * based on the specified validation mode.
     *
     * @param tenantId the tenant identifier
     * @param jdbcUrl the JDBC URL to validate
     * @param validationMode the validation mode to apply
     * @return true if validation passes, false otherwise
     */
    public static boolean validateDatabaseName(String tenantId, String jdbcUrl, 
                                                 DatabaseNameValidationMode validationMode) {
        if (validationMode == DatabaseNameValidationMode.NONE) {
            LOGGER.debug("Database name validation is disabled (mode: NONE) for tenant: {}", tenantId);
            return true;
        }
        
        if (tenantId == null || tenantId.trim().isEmpty()) {
            LOGGER.error("Tenant ID cannot be null or empty for database name validation");
            return false;
        }
        
        if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
            LOGGER.error("JDBC URL cannot be null or empty for tenant: {}", tenantId);
            return false;
        }
        
        String databaseName = extractDatabaseName(jdbcUrl);
        if (databaseName == null) {
            LOGGER.error("Could not extract database name from JDBC URL for tenant {}: {}", 
                        tenantId, jdbcUrl);
            return false;
        }

        if ("ChangeMe".equalsIgnoreCase(databaseName)) {
            LOGGER.error("Database name in JDBC URL is set to default placeholder 'ChangeMe' "
                + "will be changed to tenantId for tenant {}: {}", tenantId, jdbcUrl);
            return true;
        }
        
        boolean isValid = performValidation(tenantId, databaseName, validationMode);
        
        if (isValid) {
            LOGGER.info("Database name validation PASSED for tenant [{}] - Database: {}, Mode: {}", 
                       tenantId, databaseName, validationMode);
        } else {
            LOGGER.error("Database name validation FAILED for tenant [{}] - Database: {}, Mode: {}, Tenant ID: {}", 
                        tenantId, databaseName, validationMode, tenantId);
        }
        
        return isValid;
    }
    
    /**
     * Extracts the database name from a PostgreSQL JDBC URL.
     *
     * @param jdbcUrl the JDBC URL
     * @return the database name, or null if extraction fails
     */
    private static String extractDatabaseName(String jdbcUrl) {
        try {
            Matcher matcher = JDBC_URL_PATTERN.matcher(jdbcUrl);
            if (matcher.find()) {
                return matcher.group(1);
            }
            
            // Fallback: try simple extraction
            int lastSlashIndex = jdbcUrl.lastIndexOf('/');
            if (lastSlashIndex != NOT_FOUND_INDEX) {
                String afterSlash = jdbcUrl.substring(lastSlashIndex + 1);
                int questionMarkIndex = afterSlash.indexOf('?');
                if (questionMarkIndex != NOT_FOUND_INDEX) {
                    return afterSlash.substring(0, questionMarkIndex);
                }
                return afterSlash;
            }
            
            return null;
        } catch (Exception e) {
            LOGGER.error("Error extracting database name from JDBC URL: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Performs the actual validation based on the specified mode.
     *
     * @param tenantId the tenant identifier
     * @param databaseName the database name from JDBC URL
     * @param validationMode the validation mode
     * @return true if validation passes, false otherwise
     */
    private static boolean performValidation(String tenantId, String databaseName, 
                                             DatabaseNameValidationMode validationMode) {
        switch (validationMode) {
            case EQUAL:
                return databaseName.equals(tenantId);
                
            case PREFIX:
                return databaseName.startsWith(tenantId);
                
            case CONTAINS:
                return databaseName.contains(tenantId);
                
            case NONE:
            default:
                return true;
        }
    }
}
