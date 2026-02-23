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

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.env.Environment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

/**
 * Unit tests for ConfigurationPropertyUtils utility class.
 */
class ConfigurationPropertyUtilsTest {

    @Test
    void testGenerateTenantJdbcUrl_FromEnvironmentVariable() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE"))
            .thenReturn("jdbc:postgresql://envhost:5432/tenant1db");
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, null);
        
        // Then
        assertEquals("jdbc:postgresql://envhost:5432/tenant1db", result);
    }

    @Test
    void testGenerateTenantJdbcUrl_FromProperty() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://prophost:5432/tenant1db");
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, null);
        
        // Then
        assertEquals("jdbc:postgresql://prophost:5432/tenant1db", result);
    }

    @Test
    void testGenerateTenantJdbcUrl_FromTemplateUrl_WhenNoEnvVarOrProperty() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        String templateUrl = "jdbc:postgresql://globalhost:5432/defaultdb";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then
        assertEquals("jdbc:postgresql://globalhost:5432/tenant1", result);
    }

    @Test
    void testGenerateTenantJdbcUrl_FromTemplateUrlWithParams_WhenNoEnvVarOrProperty() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        String templateUrl = "jdbc:postgresql://globalhost:5432/defaultdb?ssl=true&param=value";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then
        assertEquals("jdbc:postgresql://globalhost:5432/tenant1?ssl=true&param=value", result);
    }

    @Test
    void testGenerateTenantJdbcUrl_FromTemplateUrl() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        when(environment.getProperty("postgres.jdbc.url")).thenReturn(null);
        String templateUrl = "jdbc:postgresql://templatehost:5432/defaultdb";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then
        assertEquals("jdbc:postgresql://templatehost:5432/tenant1", result);
    }

    @Test
    void testGenerateTenantJdbcUrl_FromTemplateUrlWithParams() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        when(environment.getProperty("postgres.jdbc.url")).thenReturn(null);
        String templateUrl = "jdbc:postgresql://templatehost:5432/defaultdb?ssl=true";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then
        assertEquals("jdbc:postgresql://templatehost:5432/tenant1?ssl=true", result);
    }

    @Test
    void testGenerateTenantJdbcUrl_WithHyphenInTenantId() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT_ONE_POSTGRES_DATASOURCE"))
            .thenReturn("jdbc:postgresql://host:5432/tenant_one_db");
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant-one", environment, null);
        
        // Then
        assertEquals("jdbc:postgresql://host:5432/tenant_one_db", result);
    }

    @Test
    void testGenerateTenantJdbcUrl_IgnoresChangeMe() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn("ChangeMe");
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn("ChangeMe");
        String templateUrl = "jdbc:postgresql://globalhost:5432/defaultdb";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then
        // Should fallback to template URL since ChangeMe is ignored
        assertEquals("jdbc:postgresql://globalhost:5432/tenant1", result);
    }

    @Test
    void testGenerateTenantJdbcUrl_NullTenantId() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl(null, environment, null);
        
        // Then
        assertNull(result);
    }

    @Test
    void testGenerateTenantJdbcUrl_EmptyTenantId() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("", environment, null);
        
        // Then
        assertNull(result);
    }

    @Test
    void testGenerateTenantJdbcUrl_NoSourcesAvailable() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        when(environment.getProperty("postgres.jdbc.url")).thenReturn(null);
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, null);
        
        // Then
        assertNull(result);
    }

    @Test
    void testGenerateTenantJdbcUrl_Priority() {
        // Given - all sources configured
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE"))
            .thenReturn("jdbc:postgresql://envhost:5432/tenant1db");
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://prophost:5432/tenant1db");
        when(environment.getProperty("postgres.jdbc.url"))
            .thenReturn("jdbc:postgresql://globalhost:5432/defaultdb");
        String templateUrl = "jdbc:postgresql://templatehost:5432/defaultdb";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then - should use environment variable (highest priority)
        assertEquals("jdbc:postgresql://envhost:5432/tenant1db", result);
    }
    
    @Test
    void testGetPropertyWithDefault() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("test.property", "default"))
            .thenReturn("actual-value");
        
        // When
        String result = ConfigurationPropertyUtils.getPropertyWithDefault(environment, "test.property", "default");
        
        // Then
        assertEquals("actual-value", result);
    }
    
    @Test
    void testGetBooleanProperty() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("test.boolean", Boolean.class, false))
            .thenReturn(true);
        
        // When
        boolean result = ConfigurationPropertyUtils.getBooleanProperty(environment, "test.boolean", false);
        
        // Then
        assertTrue(result);
    }
    
    @Test
    void testIsPropertyDefined_ValidValue() {
        assertTrue(ConfigurationPropertyUtils.isPropertyDefined("valid-value"));
    }
    
    @Test
    void testIsPropertyDefined_ChangeMe() {
        assertFalse(ConfigurationPropertyUtils.isPropertyDefined("ChangeMe"));
    }
    
    @Test
    void testIsPropertyDefined_Null() {
        assertFalse(ConfigurationPropertyUtils.isPropertyDefined(null));
    }
    
    @Test
    void testIsPropertyDefined_Empty() {
        assertFalse(ConfigurationPropertyUtils.isPropertyDefined(""));
    }
    
    @Test
    void testIsPropertyDefined_Whitespace() {
        assertFalse(ConfigurationPropertyUtils.isPropertyDefined("   "));
    }
    
    @Test
    void testConstructTenantPropertyKey() {
        String result = ConfigurationPropertyUtils.constructTenantPropertyKey("tenant1", "jdbc-url");
        assertEquals("tenants.profile.tenant1.jdbc-url", result);
    }
    
    @Test
    void testGenerateTenantJdbcUrl_WithEmptyEnvVarAndProperty() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn("");
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn("");
        String templateUrl = "jdbc:postgresql://globalhost:5432/defaultdb";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then
        assertEquals("jdbc:postgresql://globalhost:5432/tenant1", result);
    }
    
    @Test
    void testGenerateTenantJdbcUrl_WithInvalidTemplateUrl() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        String templateUrl = "invalid-url-format";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then
        assertNull(result);
    }
    
    @Test
    void testGenerateTenantJdbcUrl_WithComplexQueryParameters() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        String templateUrl = "jdbc:postgresql://host:5432/db?ssl=true&sslmode=require&currentSchema=public";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then
        assertEquals("jdbc:postgresql://host:5432/tenant1?ssl=true&sslmode=require&currentSchema=public", result);
    }
    
    @Test
    void testGenerateTenantJdbcUrl_WithEmptyTemplateUrl() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        String templateUrl = "";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then
        assertNull(result);
    }
    
    @Test
    void testGenerateTenantJdbcUrl_WhitespaceTenantId() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("   ", environment, null);
        
        // Then
        assertNull(result);
    }
    
    @Test
    void testGetPropertyWithDefault_PropertyNotFound() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("missing.property", "default-value"))
            .thenReturn("default-value");
        
        // When
        String result = ConfigurationPropertyUtils.getPropertyWithDefault(
            environment, "missing.property", "default-value");
        
        // Then
        assertEquals("default-value", result);
    }
    
    @Test
    void testGetBooleanProperty_DefaultValue() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("missing.boolean", Boolean.class, true))
            .thenReturn(true);
        
        // When
        boolean result = ConfigurationPropertyUtils.getBooleanProperty(
            environment, "missing.boolean", true);
        
        // Then
        assertTrue(result);
    }
    
    @Test
    void testGetBooleanProperty_FalseValue() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("test.boolean", Boolean.class, true))
            .thenReturn(false);
        
        // When
        boolean result = ConfigurationPropertyUtils.getBooleanProperty(
            environment, "test.boolean", true);
        
        // Then
        assertFalse(result);
    }
    
    @Test
    void testConstructTenantPropertyKey_WithComplexSuffix() {
        // When
        String result = ConfigurationPropertyUtils.constructTenantPropertyKey(
            "tenant1", "key-store.key-store-password");
        
        // Then
        assertEquals("tenants.profile.tenant1.key-store.key-store-password", result);
    }
    
    @Test
    void testGenerateTenantJdbcUrl_UrlWithPortOnly() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        String templateUrl = "jdbc:postgresql://localhost/defaultdb";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then
        assertEquals("jdbc:postgresql://localhost/tenant1", result);
    }
    
    @Test
    void testGenerateTenantJdbcUrl_UrlWithIpAddress() {
        // Given
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getProperty("TENANT1_POSTGRES_DATASOURCE")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        String templateUrl = "jdbc:postgresql://192.168.1.100:5432/defaultdb";
        
        // When
        String result = ConfigurationPropertyUtils.generateTenantJdbcUrl("tenant1", environment, templateUrl);
        
        // Then
        assertEquals("jdbc:postgresql://192.168.1.100:5432/tenant1", result);
    }
    
    @Test
    void testIsPropertyDefined_WithSpacesInValue() {
        // When & Then
        assertTrue(ConfigurationPropertyUtils.isPropertyDefined("  value with spaces  "));
    }
    
    @Test
    void testConstructorThrowsException() {
        // When & Then
        try {
            java.lang.reflect.Constructor<ConfigurationPropertyUtils> constructor =
                ConfigurationPropertyUtils.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            constructor.newInstance();
            // Should not reach here
            assertTrue(false, "Expected UnsupportedOperationException");
        } catch (Exception e) {
            assertTrue(e.getCause() instanceof UnsupportedOperationException);
        }
    }
}
