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

import org.eclipse.ecsp.sql.multitenancy.TenantContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mockStatic;

/**
 * Unit tests for MultitenantDataSource.
 *
 * @since 1.0.0
 */
@ExtendWith(MockitoExtension.class)
class MultitenantDataSourceTest {

    private MultitenantDataSource multitenantDataSource;

    @BeforeEach
    void setUp() {
        multitenantDataSource = new MultitenantDataSource();
    }

    @Test
    void testDetermineCurrentLookupKeyWithTenant() {
        // Arrange
        String expectedTenant = "test-tenant";
        
        try (MockedStatic<TenantContext> mockedTenantContext = mockStatic(TenantContext.class)) {
            mockedTenantContext.when(TenantContext::getCurrentTenant).thenReturn(expectedTenant);

            // Act
            String actualTenant = multitenantDataSource.determineCurrentLookupKey();

            // Assert
            assertEquals(expectedTenant, actualTenant);
        }
    }

    @Test
    void testDetermineCurrentLookupKeyWithNullTenant() {
        // Arrange
        try (MockedStatic<TenantContext> mockedTenantContext = mockStatic(TenantContext.class)) {
            mockedTenantContext.when(TenantContext::getCurrentTenant).thenReturn(null);

            // Act
            String actualTenant = multitenantDataSource.determineCurrentLookupKey();

            // Assert
            assertNull(actualTenant);
        }
    }

    @Test
    void testDetermineCurrentLookupKeyWithDefaultTenant() {
        // Arrange
        String defaultTenant = "ecsp";
        
        try (MockedStatic<TenantContext> mockedTenantContext = mockStatic(TenantContext.class)) {
            mockedTenantContext.when(TenantContext::getCurrentTenant).thenReturn(defaultTenant);

            // Act
            String actualTenant = multitenantDataSource.determineCurrentLookupKey();

            // Assert
            assertEquals(defaultTenant, actualTenant);
        }
    }
}
