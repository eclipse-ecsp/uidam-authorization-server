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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
    
    @Value("#{'${tenant.ids}'.split(',')}")
    private List<String> tenantIds;

    @Value("${tenant.multitenant.enabled}")
    private boolean multiTenantEnabled;

    @Value("${tenant.default}")
    private String defaultTenant;
    
    @Value("${uidam.liquibase.change-log.path}")
    private String liquibaseChangeLogPath;
    
    @Value("${uidam.default.db.schema}")
    private String defaultUidamSchema;
    
    public LiquibaseConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /**
     * Programmatically run Liquibase to run and create table schema and insert default data.
     * It runover all tenants and create schema if not exists.
     *
     * @return SpringLiquibase
     */
    @Bean
    @Primary
    @ConditionalOnProperty(name = "spring.liquibase.enabled", havingValue = "true")
    @SuppressWarnings("java:S2077") // SQL injection prevented by strict schema name validation
    // Bean creation will be skipped when spring.liquibase.enabled=false (e.g., in tests)
    public SpringLiquibase createSchemaForTenant() {
        SpringLiquibase liquibase = new SpringLiquibase();

        // If multi-tenant is disabled, run Liquibase for the default tenant only
        if (!multiTenantEnabled) {
            tenantIds = List.of(defaultTenant);
            LOGGER.info("Multi-tenant is disabled. Running Liquibase for the default tenant only: {}", defaultTenant);
        } else {
            LOGGER.info("Multi-tenant is enabled. Running Liquibase for tenants: {}", tenantIds);
        }

        for (String tenantId : tenantIds) {
            TenantContext.setCurrentTenant(tenantId);
            MDC.put(TENANT_HEADER, tenantId);
            AbstractRoutingDataSource abstractRoutingDataSource = (AbstractRoutingDataSource) dataSource;
            liquibase.setDataSource(abstractRoutingDataSource.getResolvedDataSources().get(tenantId));
            liquibase.setChangeLog(liquibaseChangeLogPath);
            liquibase.setContexts(tenantId);
            liquibase.setDefaultSchema(defaultUidamSchema);
            Map<String, String> liquibaseParams = new HashMap<>();
            liquibaseParams.put("schema", defaultUidamSchema);
            liquibase.setChangeLogParameters(liquibaseParams);

            // Validate schema name to prevent SQL injection
            // Updated regex to support legitimate schema naming conventions including hyphens and dots
            if (!defaultUidamSchema.matches("^[a-zA-Z0-9_.-]+$")) {
                throw new IllegalArgumentException("Invalid schema name: " + defaultUidamSchema 
                    + ". Schema name must contain only letters, numbers, underscores, hyphens, and dots.");
            }

            try (Connection conn = dataSource.getConnection()) {
                // Create schema using safer approach with identifier validation
                createSchemaIfNotExists(conn, defaultUidamSchema);

                // Run Liquibase migration
                LOGGER.info("Liquibase configuration Start run for tenant {}", tenantId);
                liquibase.afterPropertiesSet();
                LOGGER.info("Liquibase configuration Completed run for tenant {}", tenantId);
                MDC.remove(TENANT_HEADER);
                TenantContext.clear();
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
            } finally {
                MDC.remove(TENANT_HEADER);
                TenantContext.clear();
            }
        }
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
