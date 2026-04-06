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

package org.eclipse.ecsp.oauth2.server.core.utils;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TenantUtilsTest {
    private TenantUtils tenantUtils;

    @BeforeEach
    void setUp() {
        tenantUtils = new TenantUtils();
    }

    // Helper to reset static fields after each test
    @AfterEach
    void resetStatics() {
        // Reset to defaults
        tenantUtils = new TenantUtils();
        ReflectionTestUtils.setField(tenantUtils, "multitenantEnabled", false);
        ReflectionTestUtils.setField(tenantUtils, "defaultTenant", "ecsp");
    }

    @Test
    void testResolveTenantId_MultitenantEnabled_ValidTenantId() {
        ReflectionTestUtils.setField(tenantUtils, "multitenantEnabled", true);
        String tenantId = "tenantA";
        assertEquals(tenantId, TenantUtils.resolveTenantId(tenantId));
    }

    @Test
    void testResolveTenantId_MultitenantEnabled_NullTenantId() {
        ReflectionTestUtils.setField(tenantUtils, "multitenantEnabled", true);
        Exception ex = assertThrows(IllegalArgumentException.class, () -> TenantUtils.resolveTenantId(null));
        assertTrue(ex.getMessage().contains("TenantId is required"));
    }

    @Test
    void testResolveTenantId_MultitenantEnabled_EmptyTenantId() {
        ReflectionTestUtils.setField(tenantUtils, "multitenantEnabled", true);
        Exception ex = assertThrows(IllegalArgumentException.class, () -> TenantUtils.resolveTenantId(""));
        assertTrue(ex.getMessage().contains("TenantId is required"));
    }

    @Test
    void testResolveTenantId_MultitenantDisabled_ValidTenantId() {
        ReflectionTestUtils.setField(tenantUtils, "multitenantEnabled", false);
        String tenantId = "tenantB";
        assertEquals(tenantId, TenantUtils.resolveTenantId(tenantId));
    }

    @Test
    void testResolveTenantId_MultitenantDisabled_NullTenantId_DefaultUsed() {
        ReflectionTestUtils.setField(tenantUtils, "multitenantEnabled", false);
        ReflectionTestUtils.setField(tenantUtils, "defaultTenant", "defaultTenant");
        assertEquals("defaultTenant", TenantUtils.resolveTenantId(null));
    }

    @Test
    void testResolveTenantId_MultitenantDisabled_EmptyTenantId_DefaultUsed() {
        ReflectionTestUtils.setField(tenantUtils, "multitenantEnabled", false);
        ReflectionTestUtils.setField(tenantUtils, "defaultTenant", "defaultTenant");
        assertEquals("defaultTenant", TenantUtils.resolveTenantId(""));
    }

    @Test
    void testIsMultitenantEnabled() {
        ReflectionTestUtils.setField(tenantUtils, "multitenantEnabled", true);
        assertTrue(TenantUtils.isMultitenantEnabled());
        ReflectionTestUtils.setField(tenantUtils, "multitenantEnabled", false);
        assertFalse(TenantUtils.isMultitenantEnabled());
    }

    @Test
    void testGetDefaultTenant() {
        ReflectionTestUtils.setField(tenantUtils, "defaultTenant", "foo");
        assertEquals("foo", TenantUtils.getDefaultTenant());
        ReflectionTestUtils.setField(tenantUtils, "defaultTenant", "bar");
        assertEquals("bar", TenantUtils.getDefaultTenant());
    }
}
