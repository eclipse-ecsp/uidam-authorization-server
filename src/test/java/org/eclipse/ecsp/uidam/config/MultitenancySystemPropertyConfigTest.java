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

import org.eclipse.ecsp.sql.multitenancy.TenantDatabaseProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.core.env.Environment;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for MultitenancySystemPropertyConfig.
 * Tests system property configuration for multitenancy support.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MultitenancySystemPropertyConfigTest {

    @Mock
    private Environment environment;

    @Mock
    private Map<String, TenantDatabaseProperties> multiTenantDbProperties;

    @InjectMocks
    private MultitenancySystemPropertyConfig config;

    @BeforeEach
    void setUp() {
        // Set default field values using reflection
        ReflectionTestUtils.setField(config, "sqlMultitenancyEnabled", true);
        ReflectionTestUtils.setField(config, "tenantMultitenancyEnabled", false);
        ReflectionTestUtils.setField(config, "tenantIds", "tenant1,tenant2");
        ReflectionTestUtils.setField(config, "defaultTenantId", "default");

        // Clear system properties before each test
        System.clearProperty("multitenancy.enabled");
        System.clearProperty("multi.tenant.ids");
    }

    @AfterEach
    void tearDown() {
        // Clean up system properties after each test
        System.clearProperty("multitenancy.enabled");
        System.clearProperty("multi.tenant.ids");
    }

    @Test
    void init_shouldSetSystemPropertyForMultitenancy() {
        // Arrange
        ReflectionTestUtils.setField(config, "sqlMultitenancyEnabled", true);
        lenient().when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(false);
        lenient().when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2");
        lenient().when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // Act
        config.init();

        // Assert
        assertEquals("true", System.getProperty("multitenancy.enabled"));
    }

    @Test
    void init_shouldCallRefreshTenantSystemProperties() {
        // Arrange
        lenient().when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(false);
        lenient().when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2");
        lenient().when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // Act
        config.init();

        // Assert
        verify(environment, times(1)).getProperty("tenant.multitenant.enabled", Boolean.class, false);
    }

    @Test
    void refreshTenantSystemProperties_withMultitenancyEnabled_shouldSetTenantIds() {
        // Arrange
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(true);
        when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2,tenant3");
        when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // Mock multiTenantDbProperties
        Map<String, TenantDatabaseProperties> tenantProperties = new HashMap<>();
        TenantDatabaseProperties tenant1Props = new TenantDatabaseProperties();
        tenant1Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant1");
        tenantProperties.put("tenant1", tenant1Props);
        
        TenantDatabaseProperties tenant2Props = new TenantDatabaseProperties();
        tenant2Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant2");
        tenantProperties.put("tenant2", tenant2Props);
        
        when(multiTenantDbProperties.get("tenant1")).thenReturn(tenant1Props);
        when(multiTenantDbProperties.get("tenant2")).thenReturn(tenant2Props);

        // Act
        config.refreshTenantSystemProperties();

        // Assert
        assertEquals("tenant1,tenant2,tenant3", System.getProperty("multi.tenant.ids"));
    }

    @Test
    void refreshTenantSystemProperties_withMultitenancyDisabled_shouldSetDefaultTenant() {
        // Arrange
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(false);
        when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2");
        when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // Act
        config.refreshTenantSystemProperties();

        // Assert
        assertEquals("default", System.getProperty("multi.tenant.ids"));
    }

    @Test
    void refreshTenantSystemProperties_withEmptyTenantIds_shouldHandleGracefully() {
        // Arrange
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(true);
        when(environment.getProperty("tenant.ids", "")).thenReturn("");
        when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // Act
        config.refreshTenantSystemProperties();

        // Assert
        assertEquals("", System.getProperty("multi.tenant.ids"));
    }

    @Test
    void refreshTenantSystemProperties_withNullMultiTenantDbProperties_shouldNotThrowException() {
        // Arrange
        ReflectionTestUtils.setField(config, "multiTenantDbProperties", null);
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(true);
        when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2");
        when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // Act & Assert - Should not throw exception
        config.refreshTenantSystemProperties();

        // Verify system property is still set
        assertEquals("tenant1,tenant2", System.getProperty("multi.tenant.ids"));
    }

    @Test
    void refreshTenantSystemProperties_withCustomDefaultTenant_shouldUseCustomDefault() {
        // Arrange
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(false);
        when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2");
        when(environment.getProperty("tenant.default", "default")).thenReturn("customDefault");

        // Act
        config.refreshTenantSystemProperties();

        // Assert
        assertEquals("customDefault", System.getProperty("multi.tenant.ids"));
    }

    @Test
    void refreshTenantSystemProperties_multipleInvocations_shouldUpdateSystemProperty() {
        // Arrange
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(true);
        when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // First call
        when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2");
        config.refreshTenantSystemProperties();
        assertEquals("tenant1,tenant2", System.getProperty("multi.tenant.ids"));

        // Second call with updated tenant list
        when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2,tenant3");
        config.refreshTenantSystemProperties();

        // Assert
        assertEquals("tenant1,tenant2,tenant3", System.getProperty("multi.tenant.ids"));
    }

    @Test
    void refreshTenantSystemProperties_withTenantsHavingProperties_shouldLogTenantInfo() {
        // Arrange
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(true);
        when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2");
        when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // Mock multiTenantDbProperties with complete tenant info
        final int minPoolSizeTenant1 = 5;
        final int maxPoolSizeTenant1 = 20;
        final int minPoolSizeTenant2 = 10;
        final int maxPoolSizeTenant2 = 30;
        
        TenantDatabaseProperties tenant1Props = new TenantDatabaseProperties();
        tenant1Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant1");
        tenant1Props.setUserName("tenant1user");
        tenant1Props.setMinPoolSize(minPoolSizeTenant1);
        tenant1Props.setMaxPoolSize(maxPoolSizeTenant1);
        
        TenantDatabaseProperties tenant2Props = new TenantDatabaseProperties();
        tenant2Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant2");
        tenant2Props.setUserName("tenant2user");
        tenant2Props.setMinPoolSize(minPoolSizeTenant2);
        tenant2Props.setMaxPoolSize(maxPoolSizeTenant2);
        
        final Map<String, TenantDatabaseProperties> tenantProperties = new HashMap<>();
        tenantProperties.put("tenant1", tenant1Props);
        tenantProperties.put("tenant2", tenant2Props);
        
        when(multiTenantDbProperties.get("tenant1")).thenReturn(tenant1Props);
        when(multiTenantDbProperties.get("tenant2")).thenReturn(tenant2Props);

        // Act
        config.refreshTenantSystemProperties();

        // Assert
        final int expectedGetTenantsCalls = 2;
        assertEquals("tenant1,tenant2", System.getProperty("multi.tenant.ids"));
        verify(multiTenantDbProperties, times(expectedGetTenantsCalls)).get(anyString());
    }

    @Test
    void init_withMultitenancyDisabled_shouldSetSystemPropertyToFalse() {
        // Arrange
        ReflectionTestUtils.setField(config, "sqlMultitenancyEnabled", false);
        lenient().when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(false);
        lenient().when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2");
        lenient().when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // Act
        config.init();

        // Assert
        assertEquals("false", System.getProperty("multitenancy.enabled"));
    }

    @Test
    void refreshTenantSystemProperties_shouldReadLatestValuesFromEnvironment() {
        // Arrange - First set of values
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(true);
        when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1");
        when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // Act - First refresh
        config.refreshTenantSystemProperties();

        // Assert - First value
        assertEquals("tenant1", System.getProperty("multi.tenant.ids"));

        // Arrange - Updated values (simulating /refresh endpoint)
        final int expectedRefreshCalls = 2;
        when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2,tenant3");

        // Act - Second refresh
        config.refreshTenantSystemProperties();

        // Assert - Updated value
        assertEquals("tenant1,tenant2,tenant3", System.getProperty("multi.tenant.ids"));
        verify(environment, times(expectedRefreshCalls))
            .getProperty("tenant.multitenant.enabled", Boolean.class, false);
        verify(environment, times(expectedRefreshCalls)).getProperty("tenant.ids", "");
    }

    @Test
    void refreshTenantSystemProperties_withWhitespaceInTenantIds_shouldPreserveWhitespace() {
        // Arrange
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(true);
        when(environment.getProperty("tenant.ids", "")).thenReturn(" tenant1 , tenant2 ");
        when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // Act
        config.refreshTenantSystemProperties();

        // Assert - Should preserve whitespace as configured
        assertEquals(" tenant1 , tenant2 ", System.getProperty("multi.tenant.ids"));
    }

    @Test
    void refreshTenantSystemProperties_withNullTenantIdsFromEnvironment_shouldSetEmptyString() {
        // Arrange
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(true);
        when(environment.getProperty("tenant.ids", "")).thenReturn("");
        when(environment.getProperty("tenant.default", "default")).thenReturn("default");

        // Act
        config.refreshTenantSystemProperties();

        // Assert - Should handle empty string gracefully
        String systemProperty = System.getProperty("multi.tenant.ids");
        assertEquals("", systemProperty);
    }

    @Test
    void refreshTenantSystemProperties_toggleMultitenancy_shouldSwitchBetweenTenantsAndDefault() {
        // Arrange - Start with multitenancy enabled
        when(environment.getProperty("tenant.ids", "")).thenReturn("tenant1,tenant2");
        when(environment.getProperty("tenant.default", "default")).thenReturn("default");
        
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(true);
        config.refreshTenantSystemProperties();
        assertEquals("tenant1,tenant2", System.getProperty("multi.tenant.ids"));

        // Act - Disable multitenancy
        when(environment.getProperty("tenant.multitenant.enabled", Boolean.class, false)).thenReturn(false);
        config.refreshTenantSystemProperties();

        // Assert - Should now use default tenant
        assertEquals("default", System.getProperty("multi.tenant.ids"));
    }
}
