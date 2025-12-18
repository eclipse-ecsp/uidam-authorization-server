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

import org.eclipse.ecsp.sql.multitenancy.MultiTenantDatabaseProperties;
import org.eclipse.ecsp.sql.multitenancy.TenantDatabaseProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for TenantDatabaseConfigRefresh.
 * Tests refresh-scoped configuration management and tenant property synchronization.
 */
@ExtendWith(MockitoExtension.class)
class TenantDatabaseConfigRefreshTest {

    @Mock
    private MultiTenantDatabaseProperties sqlDaoProperties;

    private TenantDatabaseConfigRefresh config;
    private TenantDatabaseConfigRefresh.RefreshableTenantConfig refreshableConfig;

    @BeforeEach
    void setUp() {
        config = new TenantDatabaseConfigRefresh();
        refreshableConfig = new TenantDatabaseConfigRefresh.RefreshableTenantConfig();
    }

    @Test
    void refreshableTenantConfig_shouldCreateNewInstance() {
        // Act
        TenantDatabaseConfigRefresh.RefreshableTenantConfig result = config.refreshableTenantConfig();

        // Assert
        assertNotNull(result);
        assertNotNull(result.getProfile());
        assertTrue(result.getProfile().isEmpty());
    }

    @Test
    void refreshableTenantConfig_shouldHaveEmptyTenantsMapByDefault() {
        // Act
        TenantDatabaseConfigRefresh.RefreshableTenantConfig result = config.refreshableTenantConfig();

        // Assert
        assertNotNull(result.getProfile());
        assertEquals(0, result.getProfile().size());
    }

    @Test
    void syncTenantProperties_withValidProperties_shouldUpdateSqlDaoProperties() {
        // Arrange
        final Map<String, TenantDatabaseProperties> updatedTenants = new HashMap<>();
        TenantDatabaseProperties tenant1Props = new TenantDatabaseProperties();
        tenant1Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant1");
        tenant1Props.setUserName("user1");
        tenant1Props.setPassword("pass1");
        updatedTenants.put("tenant1", tenant1Props);

        refreshableConfig.setProfile(updatedTenants);

        // Act
        config.syncTenantProperties(sqlDaoProperties, refreshableConfig);

        // Assert
        verify(sqlDaoProperties).setProfile(updatedTenants);
    }

    @Test
    void syncTenantProperties_withMultipleTenants_shouldSyncAll() {
        // Arrange
        final Map<String, TenantDatabaseProperties> updatedTenants = new HashMap<>();
        
        TenantDatabaseProperties tenant1Props = new TenantDatabaseProperties();
        tenant1Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant1");
        tenant1Props.setUserName("user1");
        tenant1Props.setPassword("pass1");
        updatedTenants.put("tenant1", tenant1Props);

        TenantDatabaseProperties tenant2Props = new TenantDatabaseProperties();
        tenant2Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant2");
        tenant2Props.setUserName("user2");
        tenant2Props.setPassword("pass2");
        updatedTenants.put("tenant2", tenant2Props);

        refreshableConfig.setProfile(updatedTenants);

        // Act
        config.syncTenantProperties(sqlDaoProperties, refreshableConfig);

        // Assert
        final int expectedTenantCount = 2;
        verify(sqlDaoProperties).setProfile(updatedTenants);
        assertEquals(expectedTenantCount, updatedTenants.size());
    }

    @Test
    void syncTenantProperties_withEmptyTenants_shouldUpdateWithEmptyMap() {
        // Arrange
        Map<String, TenantDatabaseProperties> emptyTenants = new HashMap<>();
        refreshableConfig.setProfile(emptyTenants);

        // Act
        config.syncTenantProperties(sqlDaoProperties, refreshableConfig);

        // Assert
        verify(sqlDaoProperties).setProfile(emptyTenants);
    }

    @Test
    void refreshableTenantConfig_settersAndGetters_shouldWorkCorrectly() {
        // Arrange
        Map<String, TenantDatabaseProperties> tenants = new HashMap<>();
        TenantDatabaseProperties props = new TenantDatabaseProperties();
        props.setJdbcUrl("jdbc:postgresql://localhost:5432/test");
        tenants.put("test", props);

        // Act
        refreshableConfig.setProfile(tenants);

        // Assert
        assertEquals(tenants, refreshableConfig.getProfile());
        assertEquals(1, refreshableConfig.getProfile().size());
        assertTrue(refreshableConfig.getProfile().containsKey("test"));
    }

    @Test
    void syncTenantProperties_shouldLogTenantsCount() {
        // Arrange
        final Map<String, TenantDatabaseProperties> updatedTenants = new HashMap<>();
        TenantDatabaseProperties tenant1Props = new TenantDatabaseProperties();
        tenant1Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant1");
        updatedTenants.put("tenant1", tenant1Props);

        TenantDatabaseProperties tenant2Props = new TenantDatabaseProperties();
        tenant2Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant2");
        updatedTenants.put("tenant2", tenant2Props);

        TenantDatabaseProperties tenant3Props = new TenantDatabaseProperties();
        tenant3Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant3");
        updatedTenants.put("tenant3", tenant3Props);

        refreshableConfig.setProfile(updatedTenants);

        // Act
        config.syncTenantProperties(sqlDaoProperties, refreshableConfig);

        // Assert
        final int expectedTenantCount = 3;
        verify(sqlDaoProperties).setProfile(updatedTenants);
        assertEquals(expectedTenantCount, updatedTenants.size());
    }

    @Test
    void refreshableTenantConfig_shouldAllowTenantAddition() {
        // Arrange
        Map<String, TenantDatabaseProperties> initialTenants = new HashMap<>();
        TenantDatabaseProperties tenant1Props = new TenantDatabaseProperties();
        tenant1Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant1");
        initialTenants.put("tenant1", tenant1Props);
        refreshableConfig.setProfile(initialTenants);

        // Act - Add new tenant
        TenantDatabaseProperties tenant2Props = new TenantDatabaseProperties();
        tenant2Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant2");
        refreshableConfig.getProfile().put("tenant2", tenant2Props);

        // Assert
        final int expectedTenantCount = 2;
        assertEquals(expectedTenantCount, refreshableConfig.getProfile().size());
        assertTrue(refreshableConfig.getProfile().containsKey("tenant1"));
        assertTrue(refreshableConfig.getProfile().containsKey("tenant2"));
    }

    @Test
    void refreshableTenantConfig_shouldAllowTenantRemoval() {
        // Arrange
        Map<String, TenantDatabaseProperties> initialTenants = new HashMap<>();
        TenantDatabaseProperties tenant1Props = new TenantDatabaseProperties();
        tenant1Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant1");
        initialTenants.put("tenant1", tenant1Props);

        TenantDatabaseProperties tenant2Props = new TenantDatabaseProperties();
        tenant2Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant2");
        initialTenants.put("tenant2", tenant2Props);

        refreshableConfig.setProfile(initialTenants);

        // Act - Remove tenant
        refreshableConfig.getProfile().remove("tenant1");

        // Assert
        assertEquals(1, refreshableConfig.getProfile().size());
        assertFalse(refreshableConfig.getProfile().containsKey("tenant1"));
        assertTrue(refreshableConfig.getProfile().containsKey("tenant2"));
    }

    @Test
    void syncTenantProperties_withUpdatedConnectionPoolSettings_shouldSync() {
        // Arrange
        final int minPoolSize = 5;
        final int maxPoolSize = 25;
        final int connectionTimeout = 30000;
        
        final Map<String, TenantDatabaseProperties> updatedTenants = new HashMap<>();
        TenantDatabaseProperties tenant1Props = new TenantDatabaseProperties();
        tenant1Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant1");
        tenant1Props.setUserName("user1");
        tenant1Props.setPassword("pass1");
        tenant1Props.setMinPoolSize(minPoolSize);
        tenant1Props.setMaxPoolSize(maxPoolSize);
        tenant1Props.setConnectionTimeoutMs(connectionTimeout);
        updatedTenants.put("tenant1", tenant1Props);

        refreshableConfig.setProfile(updatedTenants);

        // Act
        config.syncTenantProperties(sqlDaoProperties, refreshableConfig);

        // Assert
        verify(sqlDaoProperties).setProfile(updatedTenants);
        TenantDatabaseProperties syncedProps = updatedTenants.get("tenant1");
        assertEquals(minPoolSize, syncedProps.getMinPoolSize());
        assertEquals(maxPoolSize, syncedProps.getMaxPoolSize());
        assertEquals(connectionTimeout, syncedProps.getConnectionTimeoutMs());
    }

    @Test
    void refreshableTenantConfig_shouldHandleNullTenantsMap() {
        // Act
        refreshableConfig.setProfile(null);

        // Assert
        assertNull(refreshableConfig.getProfile());
    }

    @Test
    void syncTenantProperties_shouldPreserveOriginalMap() {
        // Arrange
        Map<String, TenantDatabaseProperties> originalTenants = new HashMap<>();
        TenantDatabaseProperties tenant1Props = new TenantDatabaseProperties();
        tenant1Props.setJdbcUrl("jdbc:postgresql://localhost:5432/tenant1");
        originalTenants.put("tenant1", tenant1Props);

        refreshableConfig.setProfile(originalTenants);

        // Act
        config.syncTenantProperties(sqlDaoProperties, refreshableConfig);

        // Assert
        verify(sqlDaoProperties).setProfile(originalTenants);
        assertEquals(1, originalTenants.size());
        assertTrue(originalTenants.containsKey("tenant1"));
    }
}
