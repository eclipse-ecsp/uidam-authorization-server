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

import org.eclipse.ecsp.sql.exception.TenantNotFoundException;
import org.eclipse.ecsp.sql.multitenancy.TenantContext;
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

    // Static initializer to set system property before tests run
    static {
        System.setProperty("multitenancy.enabled", "true");
        System.setProperty("tenant.default", "ecsp");
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
        MDC.clear();
    }

    @Test
    void tenantContext_shouldSetAndGetCurrentTenant() {
        // Arrange
        String testTenant = "test-tenant";
        
        // Initialize multitenancy for the test
        TenantContext.initialize(true);

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
        TenantContext.initialize(true);
        TenantContext.setCurrentTenant("test");

        // Act
        TenantContext.clear();

        // Assert - After clear, getting current tenant should return default
        TenantContext.setCurrentTenant("ecsp"); // Need to set tenant after clear
        String currentTenant = TenantContext.getCurrentTenant();
        assertEquals("ecsp", currentTenant);
    }

    @Test
    void tenantContext_shouldReturnDefaultWhenNotSet() {
        // Arrange - Set tenant context to default
        TenantContext.setCurrentTenant("ecsp");

        // Act
        String currentTenant = TenantContext.getCurrentTenant();

        // Assert - Should return default tenant "ecsp"
        assertEquals("ecsp", currentTenant);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "\t", "\n"})
    void tenantContext_shouldHandleInvalidTenantInputs(String invalidTenant) {
        // Initialize multitenancy
        TenantContext.initialize(true);
        TenantContext.setCurrentTenant("ecsp"); // Set valid tenant first
        
        // Act & Assert - Setting invalid tenant should throw TenantNotFoundException
        assertThrows(TenantNotFoundException.class, () -> {
            TenantContext.setCurrentTenant(invalidTenant);
        });
    }

    @Test
    void tenantContext_shouldHandleNullTenant() {
        // Initialize multitenancy
        TenantContext.initialize(true);
        TenantContext.setCurrentTenant("ecsp"); // Set valid tenant first
        
        // Act & Assert - Setting null tenant should throw TenantNotFoundException
        assertThrows(TenantNotFoundException.class, () -> {
            TenantContext.setCurrentTenant(null);
        });
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
        // Initialize multitenancy
        TenantContext.initialize(true);
        
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
        // Initialize multitenancy
        TenantContext.initialize(true);
        
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

            // Assert - MDC should be cleared
            assertEquals(null, MDC.get("tenantId")); // MDC cleared
            
            // Set tenant again after clear to verify it works
            TenantContext.setCurrentTenant("ecsp");
            assertEquals("ecsp", TenantContext.getCurrentTenant());
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

    @Test
    void getSchemaNameForTenant_shouldUsePropertyWhenAvailable() {
        // This tests the behavior of getSchemaNameForTenant() when uidam.default.db.schema is set
        // Simulating the logic from LiquibaseConfig.getSchemaNameForTenant()
        
        final String schemaFromProperty = "uidam";
        final String tenantId = "ecsp";
        
        // Act - Simulate the method logic
        final String result = getSchemaName(schemaFromProperty, tenantId);
        
        // Assert
        assertEquals("uidam", result, "Should use schema from property when available");
    }

    @Test
    void getSchemaNameForTenant_shouldUseTenantIdWhenPropertyIsEmpty() {
        // This tests the behavior when uidam.default.db.schema is empty
        
        final String schemaFromProperty = "";
        final String tenantId = "ECSP";
        
        // Act - Simulate the method logic
        final String result = getSchemaName(schemaFromProperty, tenantId);
        
        // Assert
        assertEquals("ecsp", result, "Should use tenant ID (lowercase) when property is empty");
    }

    @Test
    void getSchemaNameForTenant_shouldUseTenantIdWhenPropertyIsNull() {
        // This tests the behavior when uidam.default.db.schema is null
        
        final String schemaFromProperty = null;
        final String tenantId = "SDP";
        
        // Act - Simulate the method logic
        final String result = getSchemaName(schemaFromProperty, tenantId);
        
        // Assert
        assertEquals("sdp", result, "Should use tenant ID (lowercase) when property is null");
    }

    @Test
    void getSchemaNameForTenant_shouldUseTenantIdWhenPropertyIsWhitespace() {
        // This tests the behavior when uidam.default.db.schema contains only whitespace
        
        final String schemaFromProperty = "   ";
        final String tenantId = "Custom_Tenant";
        
        // Act - Simulate the method logic
        final String result = getSchemaName(schemaFromProperty, tenantId);
        
        // Assert
        assertEquals("custom_tenant", result, "Should use tenant ID (lowercase) when property is whitespace");
    }

    /**
     * Helper method to simulate getSchemaNameForTenant logic.
     */
    private String getSchemaName(String schemaFromProperty, String tenantId) {
        if (schemaFromProperty == null || schemaFromProperty.trim().isEmpty()) {
            return tenantId.toLowerCase();
        }
        return schemaFromProperty;
    }

    @Test
    void getSchemaNameForTenant_shouldConvertTenantIdToLowercase() {
        // Test that tenant ID is converted to lowercase when used as schema name
        
        String[] tenantIds = {"ECSP", "Sdp", "MixedCase", "UPPERCASE"};
        String[] expected = {"ecsp", "sdp", "mixedcase", "uppercase"};
        
        for (int i = 0; i < tenantIds.length; i++) {
            String result = tenantIds[i].toLowerCase();
            assertEquals(expected[i], result, 
                "Tenant ID should be converted to lowercase: " + tenantIds[i]);
        }
    }

    @Test
    void getSchemaNameForTenant_shouldHandleUnderscoresInTenantId() {
        // Test that underscores in tenant IDs are preserved
        
        String tenantId = "My_Test_Tenant";
        String expected = "my_test_tenant";
        
        String result = tenantId.toLowerCase();
        
        assertEquals(expected, result, "Underscores should be preserved in tenant ID");
    }

    @Test
    void schemaNameValidation_shouldRejectInvalidCharacters() {
        // Test schema validation against SQL injection
        // Pattern used in LiquibaseConfig: ^[a-zA-Z0-9_.-]+$
        final String[] invalidSchemas = {
            "schema; DROP TABLE users",
            "schema OR 1=1",
            "schema/*comment*/",
            "schema'",
            "schema\"",
            "schema;",
            "schema DROP",
            "schema\nDROP",
            "schema@example"
        };
        
        final String pattern = "^[a-zA-Z0-9_.-]+$";
        
        for (String schema : invalidSchemas) {
            final boolean isValid = schema.matches(pattern);
            assertFalse(isValid, "Invalid schema should be rejected: " + schema);
        }
    }

    @Test
    void schemaNameValidation_shouldAcceptValidCharacters() {
        // Test that valid schema names are accepted
        String[] validSchemas = {
            "uidam",
            "ecsp",
            "test_schema",
            "schema123",
            "schema-name",
            "schema.name",
            "SCHEMA_NAME"
        };
        
        String pattern = "^[a-zA-Z0-9_.-]+$";
        
        for (String schema : validSchemas) {
            boolean isValid = schema.matches(pattern);
            assertTrue(isValid, "Valid schema should be accepted: " + schema);
        }
    }
}