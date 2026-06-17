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

import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for TenantDatabaseNameValidator.
 */
class TenantDatabaseNameValidatorTest {

    @Test
    void testValidateDatabaseName_None_AlwaysPasses() {
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            "jdbc:postgresql://localhost:5432/different_db", 
            DatabaseNameValidationMode.NONE
        ));
    }

    @Test
    void testValidateDatabaseName_Equal_ExactMatch() {
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            "jdbc:postgresql://localhost:5432/tenant1", 
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_Equal_NoMatch() {
        assertFalse(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            "jdbc:postgresql://localhost:5432/tenant2", 
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_Equal_WithQueryParams() {
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            "jdbc:postgresql://localhost:5432/tenant1?ssl=true&sslmode=require", 
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_Prefix_Matches() {
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            "jdbc:postgresql://localhost:5432/tenant1_prod", 
            DatabaseNameValidationMode.PREFIX
        ));
    }

    @Test
    void testValidateDatabaseName_Prefix_NoMatch() {
        assertFalse(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            "jdbc:postgresql://localhost:5432/prod_tenant1", 
            DatabaseNameValidationMode.PREFIX
        ));
    }

    @Test
    void testValidateDatabaseName_Contains_Matches() {
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            "jdbc:postgresql://localhost:5432/prod_tenant1_db", 
            DatabaseNameValidationMode.CONTAINS
        ));
    }

    @Test
    void testValidateDatabaseName_Contains_NoMatch() {
        assertFalse(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            "jdbc:postgresql://localhost:5432/tenant2_db", 
            DatabaseNameValidationMode.CONTAINS
        ));
    }

    @Test
    void testValidateDatabaseName_NullTenantId() {
        assertFalse(TenantDatabaseNameValidator.validateDatabaseName(
            null, 
            "jdbc:postgresql://localhost:5432/tenant1", 
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_EmptyTenantId() {
        assertFalse(TenantDatabaseNameValidator.validateDatabaseName(
            "", 
            "jdbc:postgresql://localhost:5432/tenant1", 
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_NullJdbcUrl() {
        assertFalse(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            null, 
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_EmptyJdbcUrl() {
        assertFalse(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            "", 
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_InvalidJdbcUrlFormat() {
        assertFalse(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            "invalid-jdbc-url", 
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_ComplexHostname() {
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "ecsp", 
            "jdbc:postgresql://postgres.example.com:5432/ecsp", 
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_WithUnderscoreInTenantId() {
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant_1", 
            "jdbc:postgresql://localhost:5432/tenant_1", 
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_CaseSensitive() {
        assertFalse(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1", 
            "jdbc:postgresql://localhost:5432/Tenant1", 
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_ChangeMePlaceholder_ShouldReturnTrue() {
        // "ChangeMe" placeholder is treated as valid and returns true (will be changed later)
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1",
            "jdbc:postgresql://localhost:5432/ChangeMe",
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_ChangeMePlaceholderCaseInsensitive_ShouldReturnTrue() {
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1",
            "jdbc:postgresql://localhost:5432/CHANGEME",
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_FallbackExtractionNoSlash_ShouldFail() {
        // URL without slash after host - extractDatabaseName returns null → fail
        assertFalse(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1",
            "jdbc:mysql:tenant1",
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_FallbackExtractionWithSlash_Equal() {
        // Non-postgresql URL that falls through to fallback extraction (no regex match)
        // jdbc:mysql://localhost:3306/tenant1 → fallback extracts "tenant1"
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1",
            "jdbc:mysql://localhost:3306/tenant1",
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_FallbackExtractionWithQueryParams_Equal() {
        // Non-postgresql URL with query params → fallback extracts up to '?'
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1",
            "jdbc:mysql://localhost:3306/tenant1?useSSL=false",
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_Equal_WithPort_ShouldWork() {
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "ecsp",
            "jdbc:postgresql://db.host.com:5432/ecsp",
            DatabaseNameValidationMode.EQUAL
        ));
    }

    @Test
    void testValidateDatabaseName_Prefix_WithContainsFails() {
        assertFalse(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1",
            "jdbc:postgresql://localhost:5432/tenant2_db",
            DatabaseNameValidationMode.PREFIX
        ));
    }

    @Test
    void testValidateDatabaseName_Contains_ExactMatch() {
        assertTrue(TenantDatabaseNameValidator.validateDatabaseName(
            "tenant1",
            "jdbc:postgresql://localhost:5432/tenant1",
            DatabaseNameValidationMode.CONTAINS
        ));
    }

    @Test
    void testUtilityClassCannotBeInstantiated() throws Exception {
        java.lang.reflect.Constructor<TenantDatabaseNameValidator> constructor =
            TenantDatabaseNameValidator.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        InvocationTargetException ex = assertThrows(InvocationTargetException.class,
            () -> constructor.newInstance());
        assertInstanceOf(UnsupportedOperationException.class, ex.getCause());
    }
}
