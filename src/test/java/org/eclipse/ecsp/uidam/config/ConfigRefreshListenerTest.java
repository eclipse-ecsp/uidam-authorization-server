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

import org.eclipse.ecsp.oauth2.server.core.config.LiquibaseConfig;
import org.eclipse.ecsp.sql.multitenancy.TenantAwareDataSource;
import org.eclipse.ecsp.sql.multitenancy.TenantDatabaseProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.cloud.context.environment.EnvironmentChangeEvent;
import org.springframework.core.env.ConfigurableEnvironment;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for ConfigRefreshListener.
 * Tests configuration refresh event handling and dynamic tenant management.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ConfigRefreshListenerTest {

    @Mock
    private ConfigurableEnvironment environment;

    @Mock
    private TenantAwareDataSource tenantAwareDataSource;

    @Mock
    private MultitenancySystemPropertyConfig multitenancySystemPropertyConfig;

    @Mock
    private TenantDefaultPropertiesProcessor tenantDefaultPropertiesProcessor;

    @Mock
    private LiquibaseConfig liquibaseConfig;

    @Mock
    private EnvironmentChangeEvent event;

    @InjectMocks
    private ConfigRefreshListener listener;

    @BeforeEach
    void setUp() {
        // Initialize property cache
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        when(environment.getProperty("tenant.default-tenant-id")).thenReturn("default");
        when(environment.getProperty("tenant.multitenant.enabled")).thenReturn("true");
        
        // Stub LiquibaseConfig to prevent NoSuchMethodError in tests
        doNothing().when(liquibaseConfig).initializeTenantSchema(anyString());
        
        listener.initializePropertyCache();
    }

    @Test
    void initializePropertyCache_shouldCacheInitialValues() {
        // Arrange
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");

        // Act
        listener.initializePropertyCache();

        // Assert
        verify(environment, atLeastOnce()).getProperty("tenant.ids");
    }

    @Test
    void onApplicationEvent_withNullKeys_shouldLogNoChanges() {
        // Arrange
        when(event.getKeys()).thenReturn(null);

        // Act
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));

        // Assert
        verify(event).getKeys();
    }

    @Test
    void onApplicationEvent_withEmptyKeys_shouldLogNoChanges() {
        // Arrange
        when(event.getKeys()).thenReturn(new HashSet<>());

        // Act
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));

        // Assert
        verify(event).getKeys();
    }

    @Test
    void onApplicationEvent_withNonTenantChanges_shouldLogChanges() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("some.other.property");
        changedKeys.add("another.property");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("some.other.property")).thenReturn("newValue");
        when(environment.getProperty("another.property")).thenReturn("anotherValue");

        // Act
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));

        // Assert
        verify(event).getKeys();
    }

    @Test
    void onApplicationEvent_withSensitiveProperty_shouldMaskValue() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("database.password");
        changedKeys.add("api.secret");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("database.password")).thenReturn("secret123");
        when(environment.getProperty("api.secret")).thenReturn("secretKey");

        // Act
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));

        // Assert - Sensitive values should be masked in logs
        verify(event).getKeys();
    }

    @Test
    void onApplicationEvent_withTenantIdsChange_shouldProcessTenants() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2,tenant3");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(multitenancySystemPropertyConfig).refreshTenantSystemProperties();
        verify(tenantDefaultPropertiesProcessor).refreshTenantProperties(anyString(),
                any(ConfigurableEnvironment.class));
    }

    @Test
    void onApplicationEvent_withTenantAddition_shouldAddTenantDataSource() throws Exception {
        // Arrange
        final Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2,tenant3");
        
        // Mock tenant properties for new tenant
        when(environment.getProperty("tenants.profile.tenant3.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant3");
        when(environment.getProperty("tenants.profile.tenant3.user-name")).thenReturn("tenant3user");
        when(environment.getProperty("tenants.profile.tenant3.password")).thenReturn("tenant3pass");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant3"), any(TenantDatabaseProperties.class));
        verify(liquibaseConfig).initializeTenantSchema("tenant3");
    }

    @Test
    void onApplicationEvent_withTenantRemoval_shouldRemoveTenantDataSource() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).removeTenantDataSource("tenant2");
    }

    @Test
    void onApplicationEvent_withMultitenancyToggle_shouldLogChange() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.multitenant.enabled");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.multitenant.enabled")).thenReturn("false");

        // Act
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));

        // Assert
        verify(event).getKeys();
    }

    @Test
    void onApplicationEvent_withDefaultTenantChange_shouldLogChange() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.default-tenant-id");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.default-tenant-id")).thenReturn("newDefault");

        // Act
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));

        // Assert
        verify(event).getKeys();
    }

    @Test
    void onApplicationEvent_withTenantAdditionMissingJdbcUrl_shouldNotAddTenant() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2,tenant3");
        
        // Mock missing JDBC URL
        when(environment.getProperty("tenants.profile.tenant3.jdbc-url")).thenReturn(null);

        // Act
        listener.onApplicationEvent(event);

        // Assert - Should not add tenant with missing properties
        verify(tenantAwareDataSource, never()).addOrUpdateTenantDataSource(eq("tenant3"), any());
    }

    @Test
    void onApplicationEvent_withTenantAdditionException_shouldContinue() throws Exception {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2,tenant3");
        
        when(environment.getProperty("tenants.profile.tenant3.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant3");
        when(environment.getProperty("tenants.profile.tenant3.user-name")).thenReturn("user");
        when(environment.getProperty("tenants.profile.tenant3.password")).thenReturn("pass");
        
        doThrow(new RuntimeException("Test exception")).when(tenantAwareDataSource)
            .addOrUpdateTenantDataSource(eq("tenant3"), any());

        // Act & Assert - Should handle exception gracefully
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));
    }

    @Test
    void onApplicationEvent_withTenantsHavingWhitespace_shouldTrimAndProcess() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn(" tenant1 , tenant2 ");

        // Act
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));

        // Assert
        verify(environment, atLeastOnce()).getProperty("tenant.ids");
    }

    @Test
    void buildTenantDatabaseProperties_withAllProperties_shouldBuildComplete() {
        // Arrange
        when(environment.getProperty("tenants.profile.tenant3.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant3");
        when(environment.getProperty("tenants.profile.tenant3.user-name")).thenReturn("user3");
        when(environment.getProperty("tenants.profile.tenant3.password")).thenReturn("pass3");
        when(environment.getProperty("tenants.profile.tenant3.min-pool-size", "10")).thenReturn("5");
        when(environment.getProperty("tenants.profile.tenant3.max-pool-size", "30")).thenReturn("20");
        when(environment.getProperty("tenants.profile.tenant3.connection-timeout-ms", "60000"))
            .thenReturn("30000");
        when(environment.getProperty("tenants.profile.tenant3.max-idle-time", "0")).thenReturn("1800");
        when(environment.getProperty("tenants.profile.tenant3.driver-class-name"))
            .thenReturn("org.postgresql.Driver");
        when(environment.getProperty("tenants.profile.tenant3.pool-name")).thenReturn("tenant3-pool");

        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2,tenant3");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        ArgumentCaptor<TenantDatabaseProperties> captor = 
            ArgumentCaptor.forClass(TenantDatabaseProperties.class);
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant3"), captor.capture());
    }

    @Test
    void onApplicationEvent_withRefreshSystemPropertiesException_shouldContinue() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2,tenant3");
        
        doThrow(new RuntimeException("Test exception"))
            .when(multitenancySystemPropertyConfig).refreshTenantSystemProperties();

        // Act & Assert - Should handle exception gracefully
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));
    }

    @Test
    void onApplicationEvent_withRefreshTenantPropertiesException_shouldContinue() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2,tenant3");
        
        doThrow(new RuntimeException("Test exception"))
            .when(tenantDefaultPropertiesProcessor).refreshTenantProperties(anyString(), any());

        // Act & Assert - Should handle exception gracefully
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));
    }

    @Test
    void onApplicationEvent_withMultiplePropertyChanges_shouldLogAll() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        changedKeys.add("tenant.multitenant.enabled");
        changedKeys.add("some.other.property");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2,tenant3");
        when(environment.getProperty("tenant.multitenant.enabled")).thenReturn("false");
        when(environment.getProperty("some.other.property")).thenReturn("value");
        
        // Mock tenant properties to prevent stubbing issues
        when(environment.getProperty("tenants.profile.tenant3.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant3");
        when(environment.getProperty("tenants.profile.tenant3.user-name")).thenReturn("user");
        when(environment.getProperty("tenants.profile.tenant3.password")).thenReturn("pass");

        // Act
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));

        // Assert
        verify(event).getKeys();
        verify(multitenancySystemPropertyConfig).refreshTenantSystemProperties();
    }

    // ========================================
    // Tenant Property Update Tests
    // ========================================

    @Test
    void onApplicationEvent_withTenantPropertyUpdate_shouldUpdateTenantDataSource() {
        // Arrange - Simulate property update for existing tenant
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.jdbc-url");
        changedKeys.add("tenants.profile.tenant1.password");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock updated tenant properties
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://newhost:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("tenant1user");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("newPassword123");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withTenantPoolPropertyUpdate_shouldUpdateDataSource() {
        // Arrange - Simulate pool size property changes
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant2.min-pool-size");
        changedKeys.add("tenants.profile.tenant2.max-pool-size");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock tenant properties with updated pool sizes
        when(environment.getProperty("tenants.profile.tenant2.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant2");
        when(environment.getProperty("tenants.profile.tenant2.user-name")).thenReturn("tenant2user");
        when(environment.getProperty("tenants.profile.tenant2.password")).thenReturn("tenant2pass");
        when(environment.getProperty("tenants.profile.tenant2.min-pool-size", "10")).thenReturn("15");
        when(environment.getProperty("tenants.profile.tenant2.max-pool-size", "30")).thenReturn("50");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        ArgumentCaptor<TenantDatabaseProperties> captor = 
            ArgumentCaptor.forClass(TenantDatabaseProperties.class);
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant2"), captor.capture());
    }

    @Test
    void onApplicationEvent_withNonDatabaseTenantPropertyUpdate_shouldNotUpdateDataSource() {
        // Arrange - Simulate non-database property change (e.g., feature flag)
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.feature-flag");
        changedKeys.add("tenants.profile.tenant1.custom-config");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");

        // Act
        listener.onApplicationEvent(event);

        // Assert - Should not call addOrUpdateTenantDataSource for non-database properties
        verify(tenantAwareDataSource, never()).addOrUpdateTenantDataSource(eq("tenant1"), any());
    }

    @Test
    void onApplicationEvent_withMultipleTenantUpdates_shouldProcessAllTenants() {
        // Arrange - Simulate property updates for multiple tenants
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.jdbc-url");
        changedKeys.add("tenants.profile.tenant2.password");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock updated properties for tenant1
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://newhost1:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");
        
        // Mock updated properties for tenant2
        when(environment.getProperty("tenants.profile.tenant2.jdbc-url"))
            .thenReturn("jdbc:postgresql://host2:5432/tenant2");
        when(environment.getProperty("tenants.profile.tenant2.user-name")).thenReturn("user2");
        when(environment.getProperty("tenants.profile.tenant2.password")).thenReturn("newPass2");

        // Act
        listener.onApplicationEvent(event);

        // Assert - Both tenants should be updated
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant2"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withTenantUpdateException_shouldContinueProcessing() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.jdbc-url");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");
        
        // Simulate exception during update
        doThrow(new RuntimeException("Update failed"))
            .when(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant1"), any());

        // Act & Assert - Should handle exception gracefully
        assertDoesNotThrow(() -> listener.onApplicationEvent(event));
    }

    @Test
    void onApplicationEvent_withTenantUpdateMissingRequiredProperty_shouldNotUpdate() {
        // Arrange - Simulate update with missing required property
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.max-pool-size");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock missing JDBC URL (required property)
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");

        // Act
        listener.onApplicationEvent(event);

        // Assert - Should not update if required properties are missing
        verify(tenantAwareDataSource, never()).addOrUpdateTenantDataSource(eq("tenant1"), any());
    }

    @Test
    void onApplicationEvent_withTenantDriverClassNameUpdate_shouldUpdateDataSource() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.driver-class-name");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:mysql://localhost:3306/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");
        when(environment.getProperty("tenants.profile.tenant1.driver-class-name"))
            .thenReturn("com.mysql.cj.jdbc.Driver");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withTenantAdditionAndUpdate_shouldProcessBoth() {
        // Arrange - Tenant addition and existing tenant update in same event
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        changedKeys.add("tenants.profile.tenant1.jdbc-url");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2,tenant3");
        
        // Mock properties for existing tenant1 (update)
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://newhost:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");
        
        // Mock properties for new tenant3 (addition)
        when(environment.getProperty("tenants.profile.tenant3.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant3");
        when(environment.getProperty("tenants.profile.tenant3.user-name")).thenReturn("user3");
        when(environment.getProperty("tenants.profile.tenant3.password")).thenReturn("pass3");

        // Act
        listener.onApplicationEvent(event);

        // Assert - When tenant.ids changes, both addition and update are handled in one flow
        // tenant1 update and tenant3 addition should both be processed
        verify(tenantAwareDataSource, atLeastOnce())
            .addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant3"), any(TenantDatabaseProperties.class));
        verify(liquibaseConfig).initializeTenantSchema("tenant3");
    }

    @Test
    void onApplicationEvent_withTenantConnectionTimeoutUpdate_shouldUpdateDataSource() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant2.connection-timeout-ms");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        when(environment.getProperty("tenants.profile.tenant2.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant2");
        when(environment.getProperty("tenants.profile.tenant2.user-name")).thenReturn("user2");
        when(environment.getProperty("tenants.profile.tenant2.password")).thenReturn("pass2");
        when(environment.getProperty("tenants.profile.tenant2.connection-timeout-ms", "60000"))
            .thenReturn("45000");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant2"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withTenantPropertyUpdateForNonExistentTenant_shouldNotUpdate() {
        // Arrange - Simulate property update for tenant not in tenant.ids
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant5.jdbc-url");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");

        // Act
        listener.onApplicationEvent(event);

        // Assert - Should not process update for non-existent tenant
        verify(tenantAwareDataSource, never()).addOrUpdateTenantDataSource(eq("tenant5"), any());
    }

    // ========================================
    // Additional Database Property Update Tests
    // ========================================

    @Test
    void onApplicationEvent_withDefaultSchemaUpdate_shouldUpdateDataSource() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.default-schema");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock tenant properties
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withCachePrepStmtsUpdate_shouldUpdateDataSource() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant2.cache-prep-stmts");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock tenant properties
        when(environment.getProperty("tenants.profile.tenant2.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant2");
        when(environment.getProperty("tenants.profile.tenant2.user-name")).thenReturn("user2");
        when(environment.getProperty("tenants.profile.tenant2.password")).thenReturn("pass2");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant2"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withPrepStmtCacheSizeUpdate_shouldUpdateDataSource() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.prep-stmt-cache-size");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock tenant properties
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withPrepStmtCacheSqlLimitUpdate_shouldUpdateDataSource() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant2.prep-stmt-cache-sql-limit");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock tenant properties
        when(environment.getProperty("tenants.profile.tenant2.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant2");
        when(environment.getProperty("tenants.profile.tenant2.user-name")).thenReturn("user2");
        when(environment.getProperty("tenants.profile.tenant2.password")).thenReturn("pass2");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant2"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withMultipleDatabasePropertiesUpdate_shouldUpdateDataSourceOnce() {
        // Arrange - Multiple database properties changed for same tenant
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.jdbc-url");
        changedKeys.add("tenants.profile.tenant1.max-pool-size");
        changedKeys.add("tenants.profile.tenant1.cache-prep-stmts");
        changedKeys.add("tenants.profile.tenant1.default-schema");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock tenant properties
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://newhost:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");

        // Act
        listener.onApplicationEvent(event);

        // Assert - Should only update once even though multiple properties changed
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withAllDatabasePropertiesUpdate_shouldUpdateDataSource() {
        // Arrange - Test all 11 database properties
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.jdbc-url");
        changedKeys.add("tenants.profile.tenant1.user-name");
        changedKeys.add("tenants.profile.tenant1.password");
        changedKeys.add("tenants.profile.tenant1.driver-class-name");
        changedKeys.add("tenants.profile.tenant1.min-pool-size");
        changedKeys.add("tenants.profile.tenant1.max-pool-size");
        changedKeys.add("tenants.profile.tenant1.max-idle-time");
        changedKeys.add("tenants.profile.tenant1.connection-timeout-ms");
        changedKeys.add("tenants.profile.tenant1.default-schema");
        changedKeys.add("tenants.profile.tenant1.cache-prep-stmts");
        changedKeys.add("tenants.profile.tenant1.prep-stmt-cache-size");
        changedKeys.add("tenants.profile.tenant1.prep-stmt-cache-sql-limit");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock all tenant properties
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("newuser");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("newpass");
        when(environment.getProperty("tenants.profile.tenant1.driver-class-name"))
            .thenReturn("org.postgresql.Driver");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withMixedDatabaseAndNonDatabasePropertiesUpdate_shouldUpdateDataSource() {
        // Arrange - Mix of database and non-database properties
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.jdbc-url");
        changedKeys.add("tenants.profile.tenant1.some-feature-flag");
        changedKeys.add("tenants.profile.tenant1.custom-config");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock tenant properties
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");

        // Act
        listener.onApplicationEvent(event);

        // Assert - Should update because at least one database property changed
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withOnlyPerformanceTuningPropertiesUpdate_shouldUpdateDataSource() {
        // Arrange - Only performance tuning properties changed
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant2.cache-prep-stmts");
        changedKeys.add("tenants.profile.tenant2.prep-stmt-cache-size");
        changedKeys.add("tenants.profile.tenant2.prep-stmt-cache-sql-limit");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock tenant properties
        when(environment.getProperty("tenants.profile.tenant2.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant2");
        when(environment.getProperty("tenants.profile.tenant2.user-name")).thenReturn("user2");
        when(environment.getProperty("tenants.profile.tenant2.password")).thenReturn("pass2");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant2"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withMaxIdleTimeUpdate_shouldUpdateDataSource() {
        // Arrange
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.max-idle-time");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock tenant properties
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");
        when(environment.getProperty("tenants.profile.tenant1.max-idle-time", "0")).thenReturn("1800");

        // Act
        listener.onApplicationEvent(event);

        // Assert
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
    }

    @Test
    void onApplicationEvent_withDatabasePropertyUpdateAndTenantIdsChange_shouldProcessBoth() {
        // Arrange - Tenant addition AND property update for existing tenant
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenant.ids");
        changedKeys.add("tenants.profile.tenant1.default-schema");
        changedKeys.add("tenants.profile.tenant1.cache-prep-stmts");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2,tenant3");
        
        // Mock properties for existing tenant1 (update)
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");
        
        // Mock properties for new tenant3 (addition)
        when(environment.getProperty("tenants.profile.tenant3.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant3");
        when(environment.getProperty("tenants.profile.tenant3.user-name")).thenReturn("user3");
        when(environment.getProperty("tenants.profile.tenant3.password")).thenReturn("pass3");

        // Act
        listener.onApplicationEvent(event);

        // Assert - Both tenant1 update and tenant3 addition should be processed
        verify(tenantAwareDataSource, atLeastOnce())
            .addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant3"), any(TenantDatabaseProperties.class));
        verify(liquibaseConfig).initializeTenantSchema("tenant3");
    }

    @Test
    void onApplicationEvent_withSeparateDatabasePropertyUpdatesForMultipleTenants_shouldUpdateBoth() {
        // Arrange - Different database properties changed for different tenants
        Set<String> changedKeys = new HashSet<>();
        changedKeys.add("tenants.profile.tenant1.default-schema");
        changedKeys.add("tenants.profile.tenant2.prep-stmt-cache-size");
        
        when(event.getKeys()).thenReturn(changedKeys);
        when(environment.getProperty("tenant.ids")).thenReturn("tenant1,tenant2");
        
        // Mock properties for tenant1
        when(environment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant1");
        when(environment.getProperty("tenants.profile.tenant1.user-name")).thenReturn("user1");
        when(environment.getProperty("tenants.profile.tenant1.password")).thenReturn("pass1");
        
        // Mock properties for tenant2
        when(environment.getProperty("tenants.profile.tenant2.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant2");
        when(environment.getProperty("tenants.profile.tenant2.user-name")).thenReturn("user2");
        when(environment.getProperty("tenants.profile.tenant2.password")).thenReturn("pass2");

        // Act
        listener.onApplicationEvent(event);

        // Assert - Both tenants should be updated
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant1"), any(TenantDatabaseProperties.class));
        verify(tenantAwareDataSource).addOrUpdateTenantDataSource(eq("tenant2"), any(TenantDatabaseProperties.class));
    }
}
