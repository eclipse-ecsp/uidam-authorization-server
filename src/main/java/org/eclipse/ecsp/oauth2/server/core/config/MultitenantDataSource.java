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

package org.eclipse.ecsp.oauth2.server.core.config;

import org.eclipse.ecsp.sql.multitenancy.TenantContext;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;

/**
 * Custom AbstractRoutingDatasource Configuration for the Multi-tenancy.
 * This class routes database connections based on the current tenant context,
 * enabling multi-tenant data isolation at the database level.
 */
public class MultitenantDataSource extends AbstractRoutingDataSource {

    /**
     * Determines the current lookup key for routing to the appropriate datasource.
     * This method is called by Spring's AbstractRoutingDataSource to determine
     * which target datasource should be used for the current request.
     *
     * @return the current tenant identifier used as the datasource lookup key,
     *         or null if no tenant is currently set in the context
     */
    @Override
    protected String determineCurrentLookupKey() {
        return TenantContext.getCurrentTenant();
    }
}
