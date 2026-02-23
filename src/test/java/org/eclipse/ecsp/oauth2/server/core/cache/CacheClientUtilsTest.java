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

package org.eclipse.ecsp.oauth2.server.core.cache;

import org.eclipse.ecsp.oauth2.server.core.cache.impl.CacheClientServiceImpl;
import org.eclipse.ecsp.sql.multitenancy.TenantContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;

/**
 * This class tests the functionality of the CacheClientUtils.
 */
@SpringBootTest
@ContextConfiguration(classes = { CacheClientUtils.class })
class CacheClientUtilsTest {

    @Autowired
    private CacheClientUtils cacheClientUtils;

    @MockitoBean
    CacheClientServiceImpl cacheClientService;

    /**
     * This method sets up the test environment before each test.
     * It initializes the mocks and sets up tenant context.
     */
    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
        // Set up tenant context for multi-tenancy tests
        TenantContext.setCurrentTenant("uidam");
    }

    /**
     * Clean up tenant context after each test.
     */
    @AfterEach
    void tearDown() {
        // Clean up tenant context after each test
        TenantContext.clear();
    }

    /**
     * Tests the retrieval of client details.
     * It mocks the CacheClientServiceImpl to return predefined client details and verifies that the cacheClientUtils
     * correctly retrieves and maps these details to a ClientCacheDetails instance.
     */
    @Test
    void getClientDetails() {
        doReturn(new ClientCacheDetails()).when(cacheClientService).getClientDetailsWithoutSync(anyString(),
                anyString());
        ClientCacheDetails clientCacheDetails = cacheClientUtils.getClientDetails("token-mgmt");
        assertNotNull(clientCacheDetails);
    }

}