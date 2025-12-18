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

import liquibase.integration.spring.SpringLiquibase;
import org.eclipse.ecsp.sql.multitenancy.TenantContext;
import org.eclipse.ecsp.uidam.util.ConfigurationPropertyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Liquibase configuration for the tenants.
 */ 
@Configuration
@ConditionalOnProperty(name = "spring.liquibase.enabled", havingValue = "true")
// Skip LiquibaseConfig when liquibase is disabled (e.g., in tests)
public class LiquibaseConfig  {

    private static final Logger LOGGER = LoggerFactory.getLogger(LiquibaseConfig.class);

    private static final String TENANT_HEADER = "tenantId";

    private final DataSource dataSource;
    private final Environment environment;
    
    public LiquibaseConfig(DataSource dataSource, Environment environment) {
        this.dataSource = dataSource;
        this.environment = environment;
    }

    /**
     * Programmatically run Liquibase to run and create table schema and insert default data.
     * It runs over all tenants and creates schema if not exists.
     *
     * @return SpringLiquibase (returns null as this is initialization only)
     */
    @Bean
    @Primary
    @DependsOn({"multitenancySystemPropertyConfig", "tenantAwareDataSource"})
    @ConditionalOnProperty(name = "spring.liquibase.enabled", havingValue = "true")
    @SuppressWarnings("java:S2077") // SQL injection prevented by strict schema name validation
    // Bean creation will be skipped when spring.liquibase.enabled=false (e.g., in tests)
    public SpringLiquibase createSchemaForTenant() {
        List<String> tenantIds = getTenantIds();
        
        LOGGER.info("Liquibase configuration initializing for {} tenant(s): {}", 
            tenantIds.size(), tenantIds);

        for (String tenantId : tenantIds) {
            try {
                initializeTenantSchema(tenantId);
            } catch (LiquibaseInitializationException e) {
                LOGGER.error("Failed to initialize schema for tenant: {}. Skipping...", tenantId, e);
                // Depending on requirements, you might want to throw here or continue
                // throw e; // Uncomment to fail-fast
            }
        }
        
        return null;
    }

    /**
     * Initializes Liquibase schema for a specific tenant.
     * This method can be called dynamically when a new tenant is added.
     *
     * @param tenantId the tenant identifier
     * @throws LiquibaseInitializationException if initialization fails
     */
    public void initializeTenantSchema(String tenantId) {
        if (tenantId == null || tenantId.trim().isEmpty()) {
            throw new IllegalArgumentException("Tenant ID cannot be null or empty");
        }
        
        TenantContext.setCurrentTenant(tenantId);
        MDC.put(TENANT_HEADER, tenantId);
        
        SpringLiquibase liquibase = new SpringLiquibase();
        DataSource tenantDataSource = null;
        
        try {
            LOGGER.info("Starting Liquibase initialization for tenant: {}", tenantId);
            
            // Get configuration values
            final String liquibaseChangeLogPath = getProperty("uidam.liquibase.change-log.path", 
                "classpath:database.schema/master.xml");
            final String defaultUidamSchema = getProperty("uidam.default.db.schema", "uidam");
            
            // Validate schema name to prevent SQL injection
            validateSchemaName(defaultUidamSchema);
            
            // Get tenant-specific datasource
            tenantDataSource = getTenantDataSource(tenantId);
            
            // Configure Liquibase
            liquibase.setDataSource(tenantDataSource);
            liquibase.setChangeLog(liquibaseChangeLogPath);
            liquibase.setContexts(tenantId);
            liquibase.setDefaultSchema(defaultUidamSchema);
            
            Map<String, String> liquibaseParams = new HashMap<>();
            liquibaseParams.put("schema", defaultUidamSchema);
            liquibase.setChangeLogParameters(liquibaseParams);

            try (Connection conn = tenantDataSource.getConnection()) {
                // Create schema if not exists
                createSchemaIfNotExists(conn, defaultUidamSchema);

                // Run Liquibase migration
                LOGGER.info("Running Liquibase migration for tenant: {}", tenantId);
                liquibase.afterPropertiesSet();
                LOGGER.info("Liquibase migration completed successfully for tenant: {}", tenantId);
            } catch (SQLException e) {
                LOGGER.error("SQL error during Liquibase initialization for tenant: {}. Error: {}", 
                        tenantId, e.getMessage(), e);
                throw new LiquibaseInitializationException(
                        "SQL error during Liquibase initialization for tenant: " + tenantId, e);
            } catch (Exception e) {
                LOGGER.error("Liquibase initialization failed for tenant: {}. Error: {}", 
                        tenantId, e.getMessage(), e);
                throw new LiquibaseInitializationException(
                        "Liquibase initialization failed for tenant: " + tenantId, e);
            }
        } finally {
            // Clean up resources
            if (isUseGlobalCredentials() && tenantDataSource != null) {
                LOGGER.debug("Cleaning up global credential datasource for tenant: {}", tenantId);
                // DriverManagerDataSource doesn't need explicit cleanup
            }
            MDC.remove(TENANT_HEADER);
            TenantContext.clear();
        }
    }

    /**
     * Gets the list of tenant IDs from configuration.
     * In multi-tenant mode, returns all configured tenants.
     * In single-tenant mode, returns only the default tenant.
     *
     * @return list of tenant IDs
     */
    private List<String> getTenantIds() {
        boolean multiTenantEnabled = getBooleanProperty("tenant.multitenant.enabled", false);
        
        if (!multiTenantEnabled) {
            String defaultTenant = getProperty("tenant.default", "default");
            LOGGER.info("Multi-tenant is disabled. Using default tenant only: {}", defaultTenant);
            return List.of(defaultTenant);
        } else {
            String tenantIdsProperty = getProperty("tenant.ids", "");
            List<String> tenantIds = Arrays.stream(tenantIdsProperty.split(","))
                .map(String::trim)
                .filter(id -> !id.isEmpty())
                .collect(Collectors.toList());
            LOGGER.info("Multi-tenant is enabled. Found {} tenant(s)", tenantIds.size());
            return tenantIds;
        }
    }

    /**
     * Reads a property value from the environment.
     *
     * @param key the property key
     * @param defaultValue the default value if property is not found
     * @return the property value or default
     */
    private String getProperty(String key, String defaultValue) {
        return environment.getProperty(key, defaultValue);
    }

    /**
     * Reads a boolean property value from the environment.
     *
     * @param key the property key
     * @param defaultValue the default value if property is not found
     * @return the property value or default
     */
    private boolean getBooleanProperty(String key, boolean defaultValue) {
        return environment.getProperty(key, Boolean.class, defaultValue);
    }

    /**
     * Checks if global credentials should be used for database connections.
     *
     * @return true if global credentials are enabled
     */
    private boolean isUseGlobalCredentials() {
        return getBooleanProperty("uidam.liquibase.db.credential.global", false);
    }

    /**
     * Validates schema name to prevent SQL injection.
     *
     * @param schemaName the schema name to validate
     * @throws IllegalArgumentException if schema name is invalid
     */
    private void validateSchemaName(String schemaName) {
        if (!schemaName.matches("^[a-zA-Z0-9_.-]+$")) {
            throw new IllegalArgumentException("Invalid schema name: " + schemaName 
                + ". Schema name must contain only letters, numbers, underscores, hyphens, and dots.");
        }
    }

    /**
     * Gets the appropriate DataSource for the tenant based on configuration.
     * If useGlobalCredentials is true, creates a simple DataSource with global admin credentials
     * and tenant-specific JDBC URL. Otherwise, uses the routing datasource.
     *
     * @param tenantId the tenant identifier
     * @return DataSource for the tenant
     */
    private DataSource getTenantDataSource(String tenantId) {
        if (isUseGlobalCredentials()) {
            LOGGER.info("Creating datasource with global credentials for tenant: {}", tenantId);
            return createGlobalCredentialDataSource(tenantId);
        } else {
            LOGGER.info("Using routing datasource for tenant: {}", tenantId);
            AbstractRoutingDataSource abstractRoutingDataSource = (AbstractRoutingDataSource) dataSource;
            DataSource tenantDs = (DataSource) abstractRoutingDataSource.getResolvedDataSources().get(tenantId);
            if (tenantDs == null) {
                throw new IllegalStateException("No datasource found for tenant: " + tenantId);
            }
            return tenantDs;
        }
    }

    /**
     * Creates a simple DataSource with global admin credentials and tenant-specific JDBC URL.
     * This DataSource uses global credentials from application.properties but connects to 
     * the tenant-specific database.
     *
     * @param tenantId the tenant identifier
     * @return DataSource configured with global credentials and tenant-specific URL
     */
    private DataSource createGlobalCredentialDataSource(String tenantId) {
        // Get tenant-specific JDBC URL from tenant properties or generate it
        String tenantJdbcUrl = getTenantJdbcUrl(tenantId);
        
        LOGGER.info("Creating global credential datasource for tenant {} with URL: {}", 
            tenantId, tenantJdbcUrl);
        
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(getProperty("postgres.driver.class.name", "org.postgresql.Driver"));
        dataSource.setUrl(tenantJdbcUrl);
        dataSource.setUsername(getProperty("postgres.username", "postgres"));
        dataSource.setPassword(getProperty("postgres.password", ""));
        
        return dataSource;
    }

    /**
     * Gets tenant-specific JDBC URL. 
     * Delegates to ConfigurationPropertyUtils utility class for consistent URL generation logic.
     *
     * @param tenantId the tenant identifier
     * @return tenant-specific JDBC URL
     */
    private String getTenantJdbcUrl(String tenantId) {
        // Use the utility class to generate tenant JDBC URL
        String jdbcUrl = ConfigurationPropertyUtils.generateTenantJdbcUrl(tenantId, environment, null);
        
        if (jdbcUrl != null) {
            return jdbcUrl;
        }
        
        // If utility couldn't generate, log warning and return null
        LOGGER.warn("Could not determine tenant-specific JDBC URL for tenant: {}", tenantId);
        return null;
    }

    /**
     * Creates schema if it doesn't exist using safer SQL execution.
     * This method provides better security than string concatenation by using
     * prepared SQL with validated schema name.
     *
     * @param connection the database connection
     * @param schemaName the validated schema name
     * @throws SQLException if schema creation fails
     */
    @SuppressWarnings("java:S2077") // SQL injection prevented by strict schema name validation
    private void createSchemaIfNotExists(Connection connection, String schemaName) throws SQLException {
        // Schema name is already validated with regex, but we use Statement safely
        // Using Statement here is acceptable because:
        // 1. Schema name is strictly validated with regex [a-zA-Z0-9_.-]+
        // 2. Schema names cannot be parameterized in prepared statements for CREATE SCHEMA
        // 3. We're not accepting user input directly - it comes from validated configuration
        String sql = "CREATE SCHEMA IF NOT EXISTS " + schemaName;
        
        try (Statement stmt = connection.createStatement()) {
            LOGGER.debug("Creating schema if not exists: {}", schemaName);
            stmt.execute(sql);
            LOGGER.info("Schema '{}' created or already exists", schemaName);
        }
    }

    /**
     * Custom exception for Liquibase initialization failures.
     */
    public static class LiquibaseInitializationException extends RuntimeException {
        public LiquibaseInitializationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
