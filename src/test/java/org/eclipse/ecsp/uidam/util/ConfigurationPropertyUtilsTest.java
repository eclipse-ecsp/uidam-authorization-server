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
}
