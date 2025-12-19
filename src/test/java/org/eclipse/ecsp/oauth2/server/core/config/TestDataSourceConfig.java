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

package org.eclipse.ecsp.oauth2.server.core.config;

import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Test configuration to provide mock targetDataSources bean required by TenantAwareDataSource
 * in multi-tenancy setup.
 *
 * <p>This configuration should be imported by SpringBootTest classes that need database access.
 * It provides a properly mocked DataSource with Connection, Statement, and DatabaseMetaData
 * to satisfy Hibernate's requirements during test context initialization.
 *
 * @author rap
 */
@TestConfiguration
public class TestDataSourceConfig {
    
    // Static initializer to set system property before Spring context loads
    static {
        System.setProperty("multitenancy.enabled", "true");
        System.setProperty("tenant.default", "ecsp");
    }

    /**
     * Provides a mock targetDataSources bean required by TenantAwareDataSource.
     *
     * @return Map of mock datasources keyed by tenant ID
     * @throws Exception if mocking fails
     */
    @Bean("targetDataSources")
    public Map<String, javax.sql.DataSource> targetDataSources() throws Exception {
        // Provide mock targetDataSources bean required by TenantAwareDataSource
        final Map<String, javax.sql.DataSource> dataSources = new HashMap<>();
        
        // Create a mock datasource with proper connection mocking
        javax.sql.DataSource mockDataSource = Mockito.mock(javax.sql.DataSource.class);
        java.sql.Connection mockConnection = Mockito.mock(java.sql.Connection.class);
        java.sql.DatabaseMetaData mockMetaData = Mockito.mock(java.sql.DatabaseMetaData.class);
        java.sql.Statement mockStatement = Mockito.mock(java.sql.Statement.class);
        
        // Set up the mock to return a connection
        when(mockDataSource.getConnection()).thenReturn(mockConnection);
        when(mockConnection.getMetaData()).thenReturn(mockMetaData);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockMetaData.getDatabaseProductName()).thenReturn("H2");
        when(mockStatement.execute(any(String.class))).thenReturn(true);
        
        // Add a default datasource entry with key "default" as per MultitenantConstants.DEFAULT_TENANT_ID
        dataSources.put("default", mockDataSource);
        // Also add common tenant datasources
        dataSources.put("ecsp", mockDataSource);
        dataSources.put("sdp", mockDataSource);
        dataSources.put("testClient", mockDataSource);
        
        return dataSources;
    }
}
