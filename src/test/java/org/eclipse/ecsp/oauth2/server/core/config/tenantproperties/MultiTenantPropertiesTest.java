/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
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

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link MultiTenantProperties}.
 *
 * @since 1.1.1
 */
// CHECKSTYLE.OFF: MatchXpath
class MultiTenantPropertiesTest {
    
    private static final int EXPECTED_TENANT_COUNT = 2;
    
    private MultiTenantProperties multiTenantProperties;
    private TenantProperties ecspTenantProps;
    private TenantProperties demoTenantProps;
    
    /**
     * Test setup method.
     *
     * @since 1.1.1
     */
    @BeforeEach
    void setUp() {
        multiTenantProperties = new MultiTenantProperties();
        
        // Set up ECSP tenant properties  
        ecspTenantProps = new TenantProperties();
        
        // Set up Demo tenant properties
        demoTenantProps = new TenantProperties();
        
        // Create tenants map
        Map<String, TenantProperties> tenants = new HashMap<>();
        tenants.put("ecsp", ecspTenantProps);
        tenants.put("demo", demoTenantProps);
        
        multiTenantProperties.setProfile(tenants);
        multiTenantProperties.setDefaultTenantId("ecsp");
    }
    
    @Test
    void testGetTenantPropertiesWithValidTenantId() {
        TenantProperties result = multiTenantProperties.getTenantProperties("ecsp");
        
        assertNotNull(result);
        assertEquals(ecspTenantProps, result);
    }
    
    @Test
    void testGetTenantPropertiesWithInvalidTenantId() {
        TenantProperties result = multiTenantProperties.getTenantProperties("nonexistent");
        
        assertNull(result);
    }
    
    @Test
    void testGetTenantPropertiesWithNullTenantId() {
        TenantProperties result = multiTenantProperties.getTenantProperties(null);
        
        assertNull(result);
    }
    
    @Test
    void testGetDefaultTenant() {
        TenantProperties result = multiTenantProperties.getDefaultTenant();
        
        assertNotNull(result);
        assertEquals(ecspTenantProps, result);
    }
    
    @Test
    void testTenantExists() {
        assertTrue(multiTenantProperties.tenantExists("ecsp"));
        assertTrue(multiTenantProperties.tenantExists("demo"));
        assertFalse(multiTenantProperties.tenantExists("nonexistent"));
    }
    
    @Test
    void testGetAvailableTenants() {
        Set<String> availableTenants = multiTenantProperties.getAvailableTenants();
        
        assertNotNull(availableTenants);
        assertEquals(EXPECTED_TENANT_COUNT, availableTenants.size());
        assertTrue(availableTenants.contains("ecsp"));
        assertTrue(availableTenants.contains("demo"));
    }
    
    @Test
    void testDefaultConstructorAndSetters() {
        MultiTenantProperties properties = new MultiTenantProperties();
        
        assertNotNull(properties.getProfile());
        assertTrue(properties.getProfile().isEmpty());
        assertEquals("ecsp", properties.getDefaultTenantId());
        
        // Test setters
        properties.setDefaultTenantId("test");
        assertEquals("test", properties.getDefaultTenantId());
        
        Map<String, TenantProperties> newTenants = new HashMap<>();
        TenantProperties testProps = new TenantProperties();
        newTenants.put("test", testProps);
        properties.setProfile(newTenants);
        
        assertEquals(newTenants, properties.getProfile());
    }
}
// CHECKSTYLE.ON: MatchXpath