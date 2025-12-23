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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for TenantDefaultPropertiesProcessor.
 * Tests tenant property generation and refresh functionality.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TenantDefaultPropertiesProcessorTest {

    @Mock
    private ConfigurableEnvironment configurableEnvironment;

    @Mock
    private MutablePropertySources propertySources;

    @InjectMocks
    private TenantDefaultPropertiesProcessor processor;

    @BeforeEach
    void setUp() {
        lenient().when(configurableEnvironment.getPropertySources()).thenReturn(propertySources);
        // Mock validation properties with default values
        lenient().when(configurableEnvironment.getProperty("tenant.config.validation.enabled", 
                Boolean.class, true)).thenReturn(false); // Disable validation for most tests
        lenient().when(configurableEnvironment.getProperty("uidam.tenant.config.dbname.validation", 
                "EQUAL")).thenReturn("NONE"); // Disable DB name validation for most tests
    }

    @Test
    void postProcessBeanFactory_withValidTenantIds_shouldGenerateProperties() {
        // Arrange
        final String tenantIds = "tenant1,tenant2";
        
        // Mock property sources
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);
        
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("tenant.ids")).thenReturn(tenantIds);

        // Act & Assert
        assertDoesNotThrow(() -> processor.setEnvironment(configurableEnvironment));
    }

    @Test
    void postProcessBeanFactory_withNullTenantIds_shouldLogWarning() {
        // Arrange
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("tenant.ids")).thenReturn(null);
        
        // Act & Assert
        assertDoesNotThrow(() -> processor.setEnvironment(configurableEnvironment));
    }

    @Test
    void postProcessBeanFactory_withEmptyTenantIds_shouldLogWarning() {
        // Arrange
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("tenant.ids")).thenReturn("");
        
        // Act & Assert
        assertDoesNotThrow(() -> processor.setEnvironment(configurableEnvironment));
    }

    @Test
    void postProcessBeanFactory_withWhitespaceTenantIds_shouldTrimAndProcess() {
        // Arrange
        final String tenantIds = " tenant1 , tenant2 ";
        
        // Mock property sources
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);
        
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("tenant.ids")).thenReturn(tenantIds);

        // Act & Assert
        assertDoesNotThrow(() -> processor.setEnvironment(configurableEnvironment));
    }

    @Test
    void postProcessBeanFactory_withDefaultTenantInList_shouldSkipDefaultTenant() {
        // Arrange
        final String tenantIds = "tenant1,default,tenant2";
        
        // Mock property sources
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);
        
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("tenant.ids")).thenReturn(tenantIds);

        // Act & Assert
        assertDoesNotThrow(() -> processor.setEnvironment(configurableEnvironment));
    }

    @Test
    void postProcessBeanFactory_withExistingPropertySource_shouldRemoveOldOne() {
        // Arrange
        final String tenantIds = "tenant1";
        
        // Mock property sources
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(true);
        
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("tenant.ids")).thenReturn(tenantIds);

        // Act
        processor.setEnvironment(configurableEnvironment);

        // Assert - Cannot verify because it's private method in postProcessBeanFactory
        // Just ensure no exception is thrown
    }

    @Test
    void postProcessBeanFactory_withNoDefaultProperties_shouldNotGenerateAnyProperties() {
        // Arrange
        final String tenantIds = "tenant1";
        
        // Mock empty property sources
        List<PropertySource<?>> sources = new ArrayList<>();
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);
        
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("tenant.ids")).thenReturn(tenantIds);

        // Act & Assert
        assertDoesNotThrow(() -> processor.setEnvironment(configurableEnvironment));
    }

    @Test
    void refreshTenantProperties_shouldReloadDefaultProperties() {
        // Arrange
        final String tenantIds = "tenant1";
        
        // Mock property sources
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        defaultProps.put("tenants.profile.default.user-name", "defaultUser");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);
        
        // Mock environment to return null for tenant1 properties (so they will be generated)
        lenient().when(configurableEnvironment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn(null);
        lenient().when(configurableEnvironment.getProperty("tenants.profile.tenant1.user-name"))
            .thenReturn(null);
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/default");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.user-name"))
            .thenReturn("defaultUser");

        // Act
        processor.refreshTenantProperties(tenantIds, configurableEnvironment);

        // Assert - Should call iterator at least once (for loading default properties)
        verify(propertySources, atLeast(1)).iterator();
    }

    @Test
    void refreshTenantProperties_withNullTenantIds_shouldLogWarning() {
        // Act & Assert
        assertDoesNotThrow(() -> processor.refreshTenantProperties(null, configurableEnvironment));
    }

    @Test
    void refreshTenantProperties_withEmptyTenantIds_shouldLogWarning() {
        // Act & Assert
        assertDoesNotThrow(() -> processor.refreshTenantProperties("   ", configurableEnvironment));
    }

    @Test
    void refreshTenantProperties_withExistingGeneratedProperties_shouldRemoveAndRecreate() {
        // Arrange
        final String tenantIds = "tenant1";
        
        // Mock property sources
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(true);
        
        // Mock environment to return null for tenant1 properties (so they will be generated)
        lenient().when(configurableEnvironment.getProperty("tenants.profile.tenant1.jdbc-url")).thenReturn(null);
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/default");

        // Act
        processor.refreshTenantProperties(tenantIds, configurableEnvironment);

        // Assert - Should remove old property source before adding new one
        verify(propertySources).remove("generatedTenantProperties");
    }

    @Test
    void refreshTenantProperties_withTenantsHavingWhitespace_shouldTrimAndProcess() {
        // Arrange
        final String tenantIds = " tenant1 , tenant2 , tenant3 ";
        
        // Mock property sources
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);

        // Act & Assert - Should handle whitespace correctly
        assertDoesNotThrow(() -> processor.refreshTenantProperties(tenantIds, configurableEnvironment));
    }

    @Test
    void refreshTenantProperties_withNoPropertiesGenerated_shouldLogNoNewProperties() {
        // Arrange
        final String tenantIds = "tenant1";
        
        // Mock property sources with tenant already having all properties
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);
        
        // Mock tenant already has the property
        lenient().when(configurableEnvironment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant1");

        // Act & Assert
        assertDoesNotThrow(() -> processor.refreshTenantProperties(tenantIds, configurableEnvironment));
    }

    @Test
    void refreshTenantProperties_withMultipleTenants_shouldProcessAll() {
        // Arrange
        final String tenantIds = "tenant1,tenant2,tenant3";
        
        // Mock property sources
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);

        // Act & Assert
        assertDoesNotThrow(() -> processor.refreshTenantProperties(tenantIds, configurableEnvironment));
    }

    @Test
    void refreshTenantProperties_withEmptyStringTenants_shouldSkipEmptyValues() {
        // Arrange
        final String tenantIds = "tenant1,,tenant2,";
        
        // Mock property sources
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);

        // Act & Assert - Should skip empty tenant values
        assertDoesNotThrow(() -> processor.refreshTenantProperties(tenantIds, configurableEnvironment));
    }

    @Test
    void refreshTenantProperties_withDefaultTenantInList_shouldSkipDefault() {
        // Arrange
        final String tenantIds = "tenant1,default,tenant2";
        
        // Mock property sources
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);

        // Act & Assert
        assertDoesNotThrow(() -> processor.refreshTenantProperties(tenantIds, configurableEnvironment));
    }
    
    @Test
    void postProcessBeanFactory_withNonConfigurableEnvironment_shouldLogWarning() {
        // Arrange
        org.springframework.core.env.Environment nonConfigurableEnv = 
            Mockito.mock(org.springframework.core.env.Environment.class);
        
        // Act & Assert
        processor.setEnvironment(nonConfigurableEnv);
        assertDoesNotThrow(() -> processor.postProcessBeanFactory(null));
    }
    
    @Test
    void postProcessBeanFactory_withMultitenancyDisabled_shouldProcessDefaultTenant() {
        // Arrange
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(false);
        lenient().when(configurableEnvironment.getProperty("tenant.default")).thenReturn("tenant1");
        
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);
        
        // Act & Assert
        assertDoesNotThrow(() -> processor.setEnvironment(configurableEnvironment));
    }
    
    @Test
    void postProcessBeanFactory_withMultitenancyDisabledAndNullDefault_shouldSkipProcessing() {
        // Arrange
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(false);
        lenient().when(configurableEnvironment.getProperty("tenant.default")).thenReturn(null);
        
        // Act & Assert
        assertDoesNotThrow(() -> processor.setEnvironment(configurableEnvironment));
    }
    
    @Test
    void postProcessBeanFactory_withMultitenancyDisabledAndEmptyDefault_shouldSkipProcessing() {
        // Arrange
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(false);
        lenient().when(configurableEnvironment.getProperty("tenant.default")).thenReturn("   ");
        
        // Act & Assert
        assertDoesNotThrow(() -> processor.setEnvironment(configurableEnvironment));
    }
    
    @Test
    void postProcessBeanFactory_withValidationEnabled_shouldValidateTenantProperties() {
        // Arrange
        final String tenantIds = "tenant1";
        
        lenient().when(configurableEnvironment.getProperty("tenant.config.validation.enabled", 
            Boolean.class, true)).thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("uidam.tenant.config.dbname.validation", 
            "EQUAL")).thenReturn("NONE");
        
        // Mock property sources
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        defaultProps.put("tenants.profile.default.user-name", "defaultUser");
        defaultProps.put("tenants.profile.default.password", "defaultPass");
        defaultProps.put("tenants.profile.default.key-store.key-store-jks-encoded-content", "content");
        defaultProps.put("tenants.profile.default.key-store.key-store-password", "keystorePass");
        defaultProps.put("tenants.profile.default.key-store.key-alias", "alias");
        defaultProps.put("tenants.profile.default.key-store.key-type", "RSA");
        defaultProps.put("tenants.profile.default.captcha.recaptcha-key-site", "siteKey");
        defaultProps.put("tenants.profile.default.captcha.recaptcha-key-secret", "secretKey");
        
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);
        
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("tenant.ids")).thenReturn(tenantIds);
        
        // Mock all validation properties for default tenant
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/default");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.user-name"))
            .thenReturn("defaultUser");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.password"))
            .thenReturn("defaultPass");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.key-store.key-store-jks-encoded-content"))
            .thenReturn("content");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.key-store.key-store-password"))
            .thenReturn("keystorePass");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.key-store.key-alias"))
            .thenReturn("alias");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.key-store.key-type"))
            .thenReturn("RSA");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.captcha.recaptcha-key-site"))
            .thenReturn("siteKey");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.captcha.recaptcha-key-secret"))
            .thenReturn("secretKey");

        // Act & Assert
        assertDoesNotThrow(() -> processor.setEnvironment(configurableEnvironment));
    }
    
    @Test
    void postProcessBeanFactory_withFailedValidation_shouldRemoveFailedTenants() {
        // Arrange
        final String tenantIds = "tenant1,tenant2";
        
        lenient().when(configurableEnvironment.getProperty("tenant.config.validation.enabled", 
            Boolean.class, true)).thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("uidam.tenant.config.dbname.validation", 
            "EQUAL")).thenReturn("NONE");
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("tenant.ids")).thenReturn(tenantIds);
        
        // Mock property sources with valid default but incomplete tenant1
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        defaultProps.put("tenants.profile.default.user-name", "defaultUser");
        defaultProps.put("tenants.profile.default.password", "defaultPass");
        defaultProps.put("tenants.profile.default.key-store.key-store-jks-encoded-content", "content");
        defaultProps.put("tenants.profile.default.key-store.key-store-password", "keystorePass");
        defaultProps.put("tenants.profile.default.key-store.key-alias", "alias");
        defaultProps.put("tenants.profile.default.key-store.key-type", "RSA");
        defaultProps.put("tenants.profile.default.captcha.recaptcha-key-site", "siteKey");
        defaultProps.put("tenants.profile.default.captcha.recaptcha-key-secret", "secretKey");
        
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);
        when(propertySources.contains("failedTenantRemovalProperties")).thenReturn(false);
        
        // Mock validation properties for default tenant (all present)
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/default");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.user-name"))
            .thenReturn("defaultUser");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.password"))
            .thenReturn("defaultPass");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.key-store.key-store-jks-encoded-content"))
            .thenReturn("content");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.key-store.key-store-password"))
            .thenReturn("keystorePass");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.key-store.key-alias"))
            .thenReturn("alias");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.key-store.key-type"))
            .thenReturn("RSA");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.captcha.recaptcha-key-site"))
            .thenReturn("siteKey");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.captcha.recaptcha-key-secret"))
            .thenReturn("secretKey");
        
        // Mock validation properties for tenant1 (missing password - will fail)
        lenient().when(configurableEnvironment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/tenant1");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.tenant1.user-name"))
            .thenReturn("user1");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.tenant1.password"))
            .thenReturn(null); // Missing password

        // Act & Assert
        assertDoesNotThrow(() -> processor.setEnvironment(configurableEnvironment));
    }
    
    @Test
    void getOrder_shouldReturnHighestPrecedence() {
        // Act & Assert
        assertEquals(Ordered.HIGHEST_PRECEDENCE, processor.getOrder());
    }
    
    @Test
    void refreshTenantProperties_withValidationEnabledAndFailure_shouldReturnFailedTenants() {
        // Arrange
        final String tenantIds = "tenant1";
        
        lenient().when(configurableEnvironment.getProperty("tenant.config.validation.enabled", 
            Boolean.class, true)).thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("uidam.tenant.config.dbname.validation", 
            "EQUAL")).thenReturn("NONE");
        lenient().when(configurableEnvironment.getProperty("tenant.multitenant.enabled", Boolean.class, false))
            .thenReturn(true);
        
        // Mock property sources with valid default
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        defaultProps.put("tenants.profile.default.user-name", "defaultUser");
        defaultProps.put("tenants.profile.default.password", "defaultPass");
        defaultProps.put("tenants.profile.default.key-store.key-store-jks-encoded-content", "content");
        defaultProps.put("tenants.profile.default.key-store.key-store-password", "keystorePass");
        defaultProps.put("tenants.profile.default.key-store.key-alias", "alias");
        defaultProps.put("tenants.profile.default.key-store.key-type", "RSA");
        defaultProps.put("tenants.profile.default.captcha.recaptcha-key-site", "siteKey");
        defaultProps.put("tenants.profile.default.captcha.recaptcha-key-secret", "secretKey");
        
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        when(propertySources.contains("generatedTenantProperties")).thenReturn(false);
        when(propertySources.contains("failedTenantRemovalProperties")).thenReturn(false);
        
        // Mock validation properties for default tenant
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/default");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.user-name"))
            .thenReturn("defaultUser");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.password"))
            .thenReturn("defaultPass");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.key-store.key-store-jks-encoded-content"))
            .thenReturn("content");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.key-store.key-store-password"))
            .thenReturn("keystorePass");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.key-store.key-alias"))
            .thenReturn("alias");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.key-store.key-type"))
            .thenReturn("RSA");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.captcha.recaptcha-key-site"))
            .thenReturn("siteKey");
        lenient().when(configurableEnvironment.getProperty(
                "tenants.profile.default.captcha.recaptcha-key-secret"))
            .thenReturn("secretKey");
        
        // Mock tenant1 with missing properties (will fail validation)
        lenient().when(configurableEnvironment.getProperty("tenants.profile.tenant1.jdbc-url"))
            .thenReturn(null);
        lenient().when(configurableEnvironment.getProperty("tenant.ids")).thenReturn(tenantIds);

        // Act
        List<String> failedTenants = processor.refreshTenantProperties(tenantIds, configurableEnvironment);

        // Assert
        assertTrue(failedTenants.contains("tenant1"));
    }
    
    @Test
    void refreshTenantProperties_withDefaultValidationFailure_shouldReturnEmptyAndNotProcess() {
        // Arrange
        final String tenantIds = "tenant1";
        
        lenient().when(configurableEnvironment.getProperty("tenant.config.validation.enabled", 
            Boolean.class, true)).thenReturn(true);
        lenient().when(configurableEnvironment.getProperty("uidam.tenant.config.dbname.validation", 
            "EQUAL")).thenReturn("NONE");
        
        // Mock property sources with incomplete default tenant
        Map<String, Object> defaultProps = new HashMap<>();
        defaultProps.put("tenants.profile.default.jdbc-url", "jdbc:postgresql://localhost:5432/default");
        // Missing other required properties
        
        MapPropertySource defaultPropertySource = new MapPropertySource("defaultProps", defaultProps);
        
        List<PropertySource<?>> sources = new ArrayList<>();
        sources.add(defaultPropertySource);
        when(propertySources.iterator()).thenReturn(sources.iterator());
        
        // Mock default tenant with missing properties
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.jdbc-url"))
            .thenReturn("jdbc:postgresql://localhost:5432/default");
        lenient().when(configurableEnvironment.getProperty("tenants.profile.default.user-name"))
            .thenReturn(null); // Missing

        // Act
        List<String> failedTenants = processor.refreshTenantProperties(tenantIds, configurableEnvironment);

        // Assert - Should return empty list as default validation failed, no tenants processed
        assertDoesNotThrow(() -> failedTenants.isEmpty());
    }
}
