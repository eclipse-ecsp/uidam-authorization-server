/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.client;

import io.prometheus.client.CollectorRegistry;
import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_CLIENT_BY_CLIENT_ID_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_MANAGEMENT_ENV;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the AuthManagementClient.
 */
class AuthManagementClientTest {

    @InjectMocks
    private AuthManagementClient authManagementClient;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    private AutoCloseable closeable;

    /**
     * This method sets up the test environment before each test.
     * It sets up the tenant context and mocks.
     */
    @BeforeEach
    void setup() {
        closeable = MockitoAnnotations.openMocks(this);
        // Set up tenant context for testing
        TenantContext.setCurrentTenant("ecsp");
    }
    
    private TenantProperties createMockTenantProperties() {
        TenantProperties tenantProperties = new TenantProperties();
        tenantProperties.setTenantId("ecsp");
        tenantProperties.setTenantName("ECSP Test Tenant");
        
        // Set up mock external URLs
        HashMap<String, String> externalUrls = new HashMap<>();
        externalUrls.put(TENANT_EXTERNAL_URLS_USER_MANAGEMENT_ENV, "http://localhost:8080");
        externalUrls.put(TENANT_EXTERNAL_URLS_CLIENT_BY_CLIENT_ID_ENDPOINT, "/v1/oauth2/client/{clientId}");
        tenantProperties.setExternalUrls(externalUrls);
        
        return tenantProperties;
    }

    /**
     * This method cleans up the test environment after each test.
     * It clears the tenant context and the default registry of the CollectorRegistry.
     */
    @AfterEach
    void cleanup() throws Exception {
        TenantContext.clear();
        CollectorRegistry.defaultRegistry.clear();
        
        if (closeable != null) {
            closeable.close();
        }
    }

    /**
     * This method tests the getClientDetails method of the AuthManagementClient.
     * It calls the getClientDetails method with a test client and asserts that the returned RegisteredClientDetails is
     * null (since we're not setting up a real HTTP server).
     */
    @Test
    void testGetClientDetails() {
        // Set up mock tenant properties with external URLs
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mockTenantProperties);
        
        RegisteredClientDetails rc = authManagementClient.getClientDetails("testClient");
        assertNull(rc);
    }

    /**
     * This method tests the getClientDetails method when no tenant properties are found.
     */
    @Test
    void testGetClientDetailsWithNoTenantProperties() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(null);
        
        RegisteredClientDetails rc = authManagementClient.getClientDetails("testClient");
        assertNull(rc);
    }

    /**
     * This method tests the getClientDetails method when external URLs are not configured.
     */
    @Test
    void testGetClientDetailsWithNoExternalUrls() {
        TenantProperties mockTenantProperties = new TenantProperties();
        mockTenantProperties.setTenantId("ecsp");
        mockTenantProperties.setExternalUrls(new HashMap<>());
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mockTenantProperties);
        
        RegisteredClientDetails rc = authManagementClient.getClientDetails("testClient");
        assertNull(rc);
    }

}