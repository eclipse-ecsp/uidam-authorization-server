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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.core.env.Environment;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.test.util.ReflectionTestUtils;

import javax.sql.DataSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Comprehensive test suite for MultitenantConfiguration.
 * Tests datasource configuration, property resolution, and error handling.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("MultitenantConfiguration Tests")
@SuppressWarnings({"unchecked", "rawtypes"})
class MultitenantConfigurationMainTest {

    @Mock
    private Environment environment;

    @Mock
    private ResourceLoader resourceLoader;

    @Mock
    private Resource resource;

    @Mock
    private DataSource mockDataSource;

    private MultitenantConfiguration multitenantConfiguration;

    private static final String DEFAULT_TENANT = "ecsp";
    private static final List<String> TENANT_IDS = Arrays.asList("ecsp", "sdp");
    private static final int EXPECTED_TENANT_COUNT = 2;

    @BeforeEach
    void setUp() {
        multitenantConfiguration = new MultitenantConfiguration();
        // Set fields using ReflectionTestUtils with explicit types
        try {
            ReflectionTestUtils.setField(multitenantConfiguration, "defaultTenant", DEFAULT_TENANT);
            ReflectionTestUtils.setField(multitenantConfiguration, "env", environment);
            ReflectionTestUtils.setField(multitenantConfiguration, "resourceLoader", resourceLoader); 
            ReflectionTestUtils.setField(multitenantConfiguration, "tenantIds", TENANT_IDS);
        } catch (Exception e) {
            throw new RuntimeException("Failed to setup test fields", e);
        }
    }

    @Nested
    @DisplayName("DataSource Configuration Tests")
    class DataSourceConfigurationTests {

        @Test
        @DisplayName("Should create datasource successfully with valid tenant configurations")
        void shouldCreateDataSourceWithValidConfiguration() {
            // Given - Mock environment properties for all tenants
            setupValidTenantProperties("ecsp");
            setupValidTenantProperties("sdp");

            // When
            try (MockedStatic<DataSourceBuilder> mockStatic = mockStatic(DataSourceBuilder.class)) {
                DataSourceBuilder<DataSource> mockBuilder = mock(DataSourceBuilder.class);
                mockStatic.when(DataSourceBuilder::create).thenReturn(mockBuilder);
                
                when(mockBuilder.driverClassName(anyString())).thenReturn(mockBuilder);
                when(mockBuilder.username(anyString())).thenReturn(mockBuilder);
                when(mockBuilder.password(anyString())).thenReturn(mockBuilder);
                when(mockBuilder.url(anyString())).thenReturn(mockBuilder);
                when(mockBuilder.build()).thenReturn(mockDataSource);

                DataSource result = invokeDataSource();

                // Then
                assertNotNull(result, "DataSource should be created successfully");
                verify(mockBuilder, times(EXPECTED_TENANT_COUNT)).build(); // Called for each tenant
            }
        }

        @Test
        @DisplayName("Should throw exception when no tenant datasources configured")
        void shouldThrowExceptionWhenNoTenantDataSources() {
            // Given - Empty tenant list
            ReflectionTestUtils.setField(multitenantConfiguration, "tenantIds", Arrays.asList());

            // When & Then
            IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> invokeDataSource());
            
            assertEquals("No tenant datasources could be configured", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception when tenant has missing database properties")
        void shouldThrowExceptionForMissingDatabaseProperties() {
            // Given - Incomplete properties (missing password)
            when(environment.getProperty("tenants.profile.ecsp.postgres.driver.class.name"))
                .thenReturn("org.postgresql.Driver");
            when(environment.getProperty("tenants.profile.ecsp.postgres.username"))
                .thenReturn("testuser");
            when(environment.getProperty("tenants.profile.ecsp.postgres.jdbc.url"))
                .thenReturn("jdbc:postgresql://localhost/test");
            // Missing password property

            // When & Then
            IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> invokeDataSource());
            
            assertTrue(exception.getMessage().contains("Problem configuring tenant datasource for ecsp"));
        }

        @Test
        @DisplayName("Should handle DataSourceBuilder creation failure")
        void shouldHandleDataSourceBuilderFailure() {
            // Given - Valid properties but builder fails
            setupValidTenantProperties("ecsp");

            try (MockedStatic<DataSourceBuilder> mockStatic = mockStatic(DataSourceBuilder.class)) {
                mockStatic.when(DataSourceBuilder::create).thenThrow(new RuntimeException("Builder failed"));

                // When & Then - Expect RuntimeException to be thrown directly
                RuntimeException exception = assertThrows(RuntimeException.class,
                    () -> invokeDataSource());
                
                assertTrue(exception.getMessage().contains("Builder failed"));
            }
        }
    }

    @Nested
    @DisplayName("Property Resolution Tests")
    class PropertyResolutionTests {

        @Test
        @DisplayName("Should resolve property from environment first")
        void shouldResolvePropertyFromEnvironmentFirst() {
            // Given
            String tenantId = "ecsp";
            String propertyKey = "postgres.username";
            String expectedValue = "env_user";
            
            when(environment.getProperty("tenants.profile.ecsp.postgres.username"))
                .thenReturn(expectedValue);

            // When
            String result = invokeResolveProperty(tenantId, propertyKey);

            // Then
            assertEquals(expectedValue, result);
            verify(resourceLoader, never()).getResource(anyString()); // Should not fallback to file
        }

        @Test
        @DisplayName("Should fallback to tenant properties file when env property not found")
        void shouldFallbackToTenantPropertiesFile() throws IOException {
            // Given
            String tenantId = "ecsp";
            String propertyKey = "postgres.username";
            String expectedValue = "file_user";
            
            when(environment.getProperty("tenants.profile.ecsp.postgres.username")).thenReturn(null);
            when(resourceLoader.getResource("classpath:tenant-ecsp.properties")).thenReturn(resource);
            when(resource.exists()).thenReturn(true);
            
            String propertiesContent = "tenants.profile.ecsp.postgres.username=" + expectedValue;
            InputStream inputStream = new ByteArrayInputStream(propertiesContent.getBytes());
            when(resource.getInputStream()).thenReturn(inputStream);

            // When
            String result = invokeResolveProperty(tenantId, propertyKey);

            // Then
            assertEquals(expectedValue, result);
            verify(resourceLoader).getResource("classpath:tenant-ecsp.properties");
        }

        @Test
        @DisplayName("Should cache tenant properties file after first load")
        void shouldCacheTenantPropertiesFile() throws IOException {
            // Given
            String tenantId = "ecsp";
            String propertyKey1 = "postgres.username";
            String propertyKey2 = "postgres.password";
            
            when(environment.getProperty(anyString())).thenReturn(null);
            when(resourceLoader.getResource("classpath:tenant-ecsp.properties")).thenReturn(resource);
            when(resource.exists()).thenReturn(true);
            
            String propertiesContent = """
                tenants.profile.ecsp.postgres.username=cached_user
                tenants.profile.ecsp.postgres.password=cached_pass
                """;
            InputStream inputStream1 = new ByteArrayInputStream(propertiesContent.getBytes());
            InputStream inputStream2 = new ByteArrayInputStream(propertiesContent.getBytes());
            when(resource.getInputStream()).thenReturn(inputStream1, inputStream2);

            // When - First call loads from file
            String result1 = invokeResolveProperty(tenantId, propertyKey1);
            // Second call should use cached properties
            String result2 = invokeResolveProperty(tenantId, propertyKey2);

            // Then
            assertEquals("cached_user", result1);
            assertEquals("cached_pass", result2);
            verify(resource, times(1)).getInputStream(); // Only called once due to caching
        }

        @Test
        @DisplayName("Should fallback to Kubernetes config map format")
        void shouldFallbackToKubernetesConfigMap() {
            // Given
            String tenantId = "ecsp";
            String propertyKey = "postgres.username";
            String expectedValue = "k8s_user";
            
            when(environment.getProperty("tenants.profile.ecsp.postgres.username")).thenReturn(null);
            when(resourceLoader.getResource("classpath:tenant-ecsp.properties")).thenReturn(resource);
            when(resource.exists()).thenReturn(false);
            when(environment.getProperty("TENANTS_PROFILE_ECSP_POSTGRES_USERNAME")).thenReturn(expectedValue);

            // When
            String result = invokeResolveProperty(tenantId, propertyKey);

            // Then
            assertEquals(expectedValue, result);
        }

        @Test
        @DisplayName("Should handle IoException when loading properties file")
        void shouldHandleIoExceptionWhenLoadingPropertiesFile() throws IOException {
            // Given
            String tenantId = "ecsp";
            String propertyKey = "postgres.username";
            
            when(environment.getProperty("tenants.profile.ecsp.postgres.username")).thenReturn(null);
            when(resourceLoader.getResource("classpath:tenant-ecsp.properties")).thenReturn(resource);
            when(resource.exists()).thenReturn(true);
            when(resource.getInputStream()).thenThrow(new IOException("File read error"));

            // When
            String result = invokeResolveProperty(tenantId, propertyKey);

            // Then
            assertNull(result, "Should return null when file loading fails");
        }

        @Test
        @DisplayName("Should return null when property not found in any source")
        void shouldReturnNullWhenPropertyNotFound() {
            // Given
            String tenantId = "ecsp";
            String propertyKey = "nonexistent.property";
            
            when(environment.getProperty(anyString())).thenReturn(null);
            when(resourceLoader.getResource("classpath:tenant-ecsp.properties")).thenReturn(resource);
            when(resource.exists()).thenReturn(false);

            // When
            String result = invokeResolveProperty(tenantId, propertyKey);

            // Then
            assertNull(result);
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should handle missing driver class name")
        void shouldHandleMissingDriverClassName() {
            // Given - Missing driver class name
            when(environment.getProperty("tenants.profile.ecsp.postgres.username"))
                .thenReturn("testuser");
            when(environment.getProperty("tenants.profile.ecsp.postgres.password"))
                .thenReturn("testpass");
            when(environment.getProperty("tenants.profile.ecsp.postgres.jdbc.url"))
                .thenReturn("jdbc:postgresql://localhost/test");
            // driver class name is null

            // When & Then
            IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> invokeDataSource());
            
            assertTrue(exception.getMessage().contains("Problem configuring tenant datasource for ecsp"));
        }

        @Test
        @DisplayName("Should handle empty string properties")
        void shouldHandleEmptyStringProperties() {
            // Given - Empty string properties
            lenient().when(environment.getProperty("tenants.profile.ecsp.postgres.driver.class.name"))
                .thenReturn("");
            lenient().when(environment.getProperty("tenants.profile.ecsp.postgres.username"))
                .thenReturn("testuser");
            lenient().when(environment.getProperty("tenants.profile.ecsp.postgres.password"))
                .thenReturn("testpass");
            lenient().when(environment.getProperty("tenants.profile.ecsp.postgres.jdbc.url"))
                .thenReturn("jdbc:postgresql://localhost/test");

            // When & Then
            IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> invokeDataSource());
            
            assertTrue(exception.getMessage().contains("Problem configuring tenant datasource for ecsp"));
        }

        @Test
        @DisplayName("Should handle whitespace-only properties")
        void shouldHandleWhitespaceOnlyProperties() {
            // Given - Whitespace-only properties
            lenient().when(environment.getProperty("tenants.profile.ecsp.postgres.driver.class.name"))
                .thenReturn("   ");
            lenient().when(environment.getProperty("tenants.profile.ecsp.postgres.username"))
                .thenReturn("testuser");
            lenient().when(environment.getProperty("tenants.profile.ecsp.postgres.password"))
                .thenReturn("testpass");
            lenient().when(environment.getProperty("tenants.profile.ecsp.postgres.jdbc.url"))
                .thenReturn("jdbc:postgresql://localhost/test");

            // When & Then
            IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> invokeDataSource());
            
            assertTrue(exception.getMessage().contains("Problem configuring tenant datasource for ecsp"));
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle mixed property sources for different tenants")
        void shouldHandleMixedPropertySourcesForDifferentTenants() throws IOException {
            // Given - ecsp from environment, sdp from file
            setupValidTenantProperties("ecsp");
            
            // SDP from file
            when(environment.getProperty("tenants.profile.sdp.postgres.driver.class.name")).thenReturn(null);
            when(environment.getProperty("tenants.profile.sdp.postgres.username")).thenReturn(null);
            when(environment.getProperty("tenants.profile.sdp.postgres.password")).thenReturn(null);
            when(environment.getProperty("tenants.profile.sdp.postgres.jdbc.url")).thenReturn(null);
            
            when(resourceLoader.getResource("classpath:tenant-sdp.properties")).thenReturn(resource);
            when(resource.exists()).thenReturn(true);
            
            String sdpPropertiesContent = """
                tenants.profile.sdp.postgres.driver.class.name=org.postgresql.Driver
                tenants.profile.sdp.postgres.username=sdp_user
                tenants.profile.sdp.postgres.password=sdp_pass
                tenants.profile.sdp.postgres.jdbc.url=jdbc:postgresql://localhost/sdp
                """;
            when(resource.getInputStream()).thenReturn(new ByteArrayInputStream(sdpPropertiesContent.getBytes()));

            // When
            try (MockedStatic<DataSourceBuilder> mockStatic = mockStatic(DataSourceBuilder.class)) {
                DataSourceBuilder<DataSource> mockBuilder = mock(DataSourceBuilder.class);
                mockStatic.when(DataSourceBuilder::create).thenReturn(mockBuilder);
                
                when(mockBuilder.driverClassName(anyString())).thenReturn(mockBuilder);
                when(mockBuilder.username(anyString())).thenReturn(mockBuilder);
                when(mockBuilder.password(anyString())).thenReturn(mockBuilder);
                when(mockBuilder.url(anyString())).thenReturn(mockBuilder);
                when(mockBuilder.build()).thenReturn(mockDataSource);

                DataSource result = invokeDataSource();

                // Then
                assertNotNull(result);
                verify(mockBuilder, times(EXPECTED_TENANT_COUNT)).build(); // Both tenants configured
            }
        }
    }

    // Helper methods
    private void setupValidTenantProperties(String tenantId) {
        lenient().when(environment.getProperty("tenants.profile." + tenantId + ".postgres.driver.class.name"))
            .thenReturn("org.postgresql.Driver");
        lenient().when(environment.getProperty("tenants.profile." + tenantId + ".postgres.username"))
            .thenReturn(tenantId + "_user");
        lenient().when(environment.getProperty("tenants.profile." + tenantId + ".postgres.password"))
            .thenReturn(tenantId + "_pass");
        lenient().when(environment.getProperty("tenants.profile." + tenantId + ".postgres.jdbc.url"))
            .thenReturn("jdbc:postgresql://localhost/" + tenantId);
    }

    private String invokeResolveProperty(String tenantId, String propertyKey) {
        return (String) ReflectionTestUtils.invokeMethod(multitenantConfiguration, 
            "resolveProperty", tenantId, propertyKey);
    }

    private DataSource invokeDataSource() {
        return (DataSource) ReflectionTestUtils.invokeMethod(multitenantConfiguration, "dataSource");
    }
}
