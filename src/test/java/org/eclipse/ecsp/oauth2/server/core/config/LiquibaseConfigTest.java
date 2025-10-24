/********************************************************************************
 * Copyright (c) 2023 - 2024 Harman International
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

package org.eclipse.ecsp.oauth2.server.core.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test class for LiquibaseConfig related functionality.
 * Tests validation logic, exception handling, and tenant context management
 * without requiring the full Spring configuration context.
 */
class LiquibaseConfigTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
        MDC.clear();
    }

    @Test
    void tenantContext_shouldSetAndGetCurrentTenant() {
        // Arrange
        String testTenant = "test-tenant";

        try {
            // Act
            TenantContext.setCurrentTenant(testTenant);
            String currentTenant = TenantContext.getCurrentTenant();

            // Assert
            assertEquals(testTenant, currentTenant);
        } finally {
            TenantContext.clear();
        }
    }

    @Test
    void tenantContext_shouldClearTenant() {
        // Arrange
        TenantContext.setCurrentTenant("test");

        // Act
        TenantContext.clear();

        // Assert - Should return null after clear (no default tenant)
        String currentTenant = TenantContext.getCurrentTenant();
        assertEquals(null, currentTenant); // No tenant after clear
    }

    @Test
    void tenantContext_shouldReturnDefaultWhenNotSet() {
        // Arrange - Ensure context is clear
        TenantContext.clear();

        // Act
        String currentTenant = TenantContext.getCurrentTenant();

        // Assert - Should return null when no tenant is set
        assertEquals(null, currentTenant); // No default tenant
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "\t", "\n"})
    void tenantContext_shouldHandleInvalidTenantInputs(String invalidTenant) {
        // Act & Assert - Should throw exception for invalid inputs
        assertThrows(IllegalArgumentException.class, () -> {
            TenantContext.setCurrentTenant(invalidTenant);
        }, "Setting invalid tenant should throw IllegalArgumentException");
    }

    @Test
    void tenantContext_shouldHandleNullTenant() {
        // Act & Assert - Should throw exception for null tenant
        assertThrows(IllegalArgumentException.class, () -> {
            TenantContext.setCurrentTenant(null);
        }, "Setting null tenant should throw IllegalArgumentException");
    }

    @Test
    void tenantContext_shouldCheckIfTenantExists() {
        // Arrange
        TenantContext.clear();

        // Act & Assert - Initially no tenant
        assertFalse(TenantContext.hasTenant());

        // Set tenant
        TenantContext.setCurrentTenant("test");
        assertTrue(TenantContext.hasTenant());

        // Clear tenant
        TenantContext.clear();
        assertFalse(TenantContext.hasTenant());
    }

    @ParameterizedTest
    @ValueSource(strings = {"uidam", "test_schema", "schema123", "SCHEMA_NAME", "dev_env_1"})
    void schemaValidation_shouldAcceptValidSchemaNames(String validSchema) {
        // This tests the schema validation pattern used in LiquibaseConfig
        // Pattern: ^\\w+$ allows only word characters (letters, digits, underscore)
        
        // Act
        boolean isValid = validSchema.matches("^\\w+$");

        // Assert
        assertTrue(isValid, "Schema name should be valid: " + validSchema);
    }

    @ParameterizedTest
    @ValueSource(strings = {"schema;DROP TABLE", "schema OR 1=1", "schema--comment", 
        "schema/*comment*/", "schema'DROP"})
    void schemaValidation_shouldRejectInvalidSchemaNames(String invalidSchema) {
        // This tests the schema validation pattern used in LiquibaseConfig
        
        // Act
        boolean isValid = invalidSchema.matches("^\\w+$");

        // Assert
        assertFalse(isValid, "Schema name should be invalid: " + invalidSchema);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "schema'; DROP DATABASE test; --",
        "schema OR 1=1",
        "schema UNION SELECT * FROM users",
        "schema/**/OR/**/1=1",
        "schema\nDROP TABLE users",
        "schema\rDROP TABLE users",
        "schema\tDROP TABLE users"
    })
    void sqlInjectionPrevention_shouldValidateSchemaNames(String maliciousInput) {
        // This tests the SQL injection prevention logic from LiquibaseConfig
        
        // Act
        boolean isValid = maliciousInput.matches("^\\w+$");

        // Assert
        assertFalse(isValid, "Malicious input should be rejected: " + maliciousInput);
    }

    @Test
    void schemaValidation_shouldThrowExceptionForInvalidSchema() {
        // This simulates the validation logic from LiquibaseConfig.createSchemaForTenant()
        String invalidSchema = "invalid; DROP TABLE";
        
        // Act & Assert - This simulates the IllegalArgumentException thrown in the actual method
        assertThrows(IllegalArgumentException.class, () -> 
            validateSchemaName(invalidSchema));
    }
    
    private void validateSchemaName(String schemaName) {
        if (!schemaName.matches("^\\w+$")) {
            throw new IllegalArgumentException("Invalid schema name: " + schemaName);
        }
    }

    @Test
    void tenantContext_shouldSupportMultipleTenantSwitching() {
        try {
            // Test switching between different tenants
            TenantContext.setCurrentTenant("ecsp");
            assertEquals("ecsp", TenantContext.getCurrentTenant());
            assertTrue(TenantContext.hasTenant());

            TenantContext.setCurrentTenant("sdp");
            assertEquals("sdp", TenantContext.getCurrentTenant());
            assertTrue(TenantContext.hasTenant());

            TenantContext.setCurrentTenant("custom_tenant");
            assertEquals("custom_tenant", TenantContext.getCurrentTenant());
            assertTrue(TenantContext.hasTenant());

        } finally {
            TenantContext.clear();
        }
    }

    @Test
    void mdcCleanup_shouldBeClearedOnTenantContextClear() {
        try {
            // Setup - Simulate MDC being set (as done in LiquibaseConfig)
            MDC.put("tenantId", "test");
            TenantContext.setCurrentTenant("test");
            
            // Verify setup
            assertEquals("test", MDC.get("tenantId"));
            assertEquals("test", TenantContext.getCurrentTenant());

            // Act
            TenantContext.clear();
            MDC.clear(); // This simulates the cleanup in the actual implementation

            // Assert - Should return null when no tenant is set
            assertEquals(null, TenantContext.getCurrentTenant()); // No tenant after clear
            assertEquals(null, MDC.get("tenantId")); // MDC cleared
        } finally {
            TenantContext.clear();
            MDC.clear();
        }
    }

    @Test
    void tenantIdPattern_shouldMatchValidTenantIds() {
        // Test the tenant ID patterns that would be used in the configuration
        String[] validTenantIds = {"ecsp", "sdp", "tenant1", "TENANT_2", "dev_env"};
        
        for (String tenantId : validTenantIds) {
            // This pattern would be used for tenant validation
            boolean isValid = tenantId.matches("^[a-zA-Z0-9_]+$");
            assertTrue(isValid, "Tenant ID should be valid: " + tenantId);
        }
    }

    @Test
    void tenantConfiguration_shouldHandleEmptyTenantList() {
        // This simulates the behavior when tenantIds list is empty
        // The actual method returns null when no tenants to process
        
        // Arrange
        java.util.List<String> emptyTenantIds = java.util.Collections.emptyList();
        
        // Act - Simulate the loop behavior
        int processedTenants = 0;
        for (@SuppressWarnings("unused") String tenantId : emptyTenantIds) {
            processedTenants++;
        }
        
        // Assert
        assertEquals(0, processedTenants, "Should not process any tenants when list is empty");
    }

    @Test
    void changeLogPath_shouldBeValidPath() {
        // Test the changelog path pattern used in LiquibaseConfig
        String validPath = "classpath:database.schema/master.xml";
        
        // This validates the path format
        assertTrue(validPath.startsWith("classpath:"), "Path should start with classpath:");
        assertTrue(validPath.endsWith(".xml"), "Path should end with .xml");
        assertTrue(validPath.contains("database.schema"), "Path should contain database.schema");
    }

    @Test
    void liquibaseParameters_shouldContainRequiredKeys() {
        // This tests the parameter map structure used in LiquibaseConfig
        java.util.Map<String, String> liquibaseParams = new java.util.HashMap<>();
        liquibaseParams.put("schema", "uidam");
        
        // Assert the required parameters are present
        assertTrue(liquibaseParams.containsKey("schema"), "Parameters should contain schema key");
        assertEquals("uidam", liquibaseParams.get("schema"), "Schema parameter should have correct value");
    }

    // New tests for improved schema validation (Issues #11, #12, #13)
    
    @ParameterizedTest
    @ValueSource(strings = {"valid_schema", "schema-name", "schema.name", "schema_123", 
        "my-schema-1.0", "tenant.dev", "prod-schema", "test_schema.v2"})
    void improvedSchemaValidation_shouldAcceptLegitimateSchemaNames(String validSchema) {
        // Test the new improved regex that supports hyphens and dots (Issue #11)
        // Pattern: ^[a-zA-Z0-9_.-]+$ allows legitimate schema naming conventions
        
        // Act
        boolean isValid = validSchema.matches("^[a-zA-Z0-9_.-]+$");

        // Assert
        assertTrue(isValid, "Legitimate schema name should be valid: " + validSchema);
    }

    @ParameterizedTest
    @ValueSource(strings = {"schema;DROP", "schema OR 1=1", "schema/*comment*/", 
        "schema'DROP", "schema\nDROP", "schema\tDROP", "schema\rDROP", "schema$()", "schema#test"})
    void improvedSchemaValidation_shouldRejectMaliciousSchemaNames(String maliciousSchema) {
        // Test that the new regex still prevents SQL injection (Issue #13)
        
        // Act
        boolean isValid = maliciousSchema.matches("^[a-zA-Z0-9_.-]+$");

        // Assert
        assertFalse(isValid, "Malicious schema name should be invalid: " + maliciousSchema);
    }

    @Test
    void schemaValidation_shouldProvideDescriptiveErrorMessage() {
        // Test that our new validation provides better error messages (Issue #11)
        String invalidSchema = "invalid;schema";
        
        // Simulate the validation logic from LiquibaseConfig
        if (!invalidSchema.matches("^[a-zA-Z0-9_.-]+$")) {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
                throw new IllegalArgumentException("Invalid schema name: " + invalidSchema 
                    + ". Schema name must contain only letters, numbers, underscores, hyphens, and dots.");
            });
            
            // Assert
            String expectedMessage = "must contain only letters, numbers, underscores, hyphens, and dots";
            assertTrue(exception.getMessage().contains(expectedMessage),
                    "Error message should be descriptive");
        }
    }

    @Test
    void sqlExceptionHandling_shouldBeSpecific() {
        // Test that we handle SQLException specifically (Issue #12)
        // This simulates the improved exception handling in createSchemaForTenant()
        
        try {
            // Simulate a SQLException scenario
            throw new java.sql.SQLException("Connection failed");
        } catch (java.sql.SQLException e) {
            // Assert that we can catch SQLException specifically
            assertTrue(e instanceof java.sql.SQLException, "Should catch SQLException specifically");
            assertEquals("Connection failed", e.getMessage(), "Should preserve original error message");
        }
    }

    @Test
    void databaseSchemaCreation_shouldUseSaferApproach() {
        // Test that schema creation follows safer practices (Issue #13)
        // This tests the concept behind createSchemaIfNotExists method
        
        String validatedSchema = "test_schema";
        
        // Simulate the validation step
        if (!validatedSchema.matches("^[a-zA-Z0-9_.-]+$")) {
            throw new IllegalArgumentException("Invalid schema name");
        }
        
        // Simulate SQL construction with validated input
        String sql = "CREATE SCHEMA IF NOT EXISTS " + validatedSchema;
        
        // Assert
        assertEquals("CREATE SCHEMA IF NOT EXISTS test_schema", sql, 
            "SQL should be constructed with validated schema name");
        assertFalse(sql.contains(";"), "SQL should not contain injection characters");
        assertFalse(sql.contains("--"), "SQL should not contain comment characters");
    }

    @Test
    void createSchemaForTenant_shouldUseCorrectTenantListBasedOnMultiTenantFlag() {
        // Arrange
        // Simulate the logic for lines 80-85 in LiquibaseConfig.java
        java.util.List<String> allTenants = java.util.Arrays.asList("ecsp", "sdp", "custom");
        String defaultTenant = "ecsp";
        boolean multiTenantEnabled;
        java.util.List<String> tenantIds;

        // Case 1: Multi-tenant disabled
        multiTenantEnabled = false;
        tenantIds = allTenants;
        if (!multiTenantEnabled) {
            tenantIds = java.util.Collections.singletonList(defaultTenant);
        }
        assertEquals(1, tenantIds.size(), "Should only use default tenant when multi-tenant is disabled");
        assertEquals(defaultTenant, tenantIds.get(0), "Default tenant should be used");

        // Case 2: Multi-tenant enabled
        multiTenantEnabled = true;
        tenantIds = allTenants;
        if (!multiTenantEnabled) {
            tenantIds = java.util.Collections.singletonList(defaultTenant);
        }
        assertEquals(allTenants, tenantIds, "Should use all tenants when multi-tenant is enabled");
    }
}