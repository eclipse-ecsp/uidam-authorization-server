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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import javax.annotation.PostConstruct;
/**
 * Configuration class to bridge Spring application properties to System properties
 * for multitenancy support.
 * This is necessary because the sql-dao library reads multitenancy.enabled from
 * System properties, while the application defines it in application.properties.
 */

@Configuration
public class MultitenancySystemPropertyConfig {

    @Value("${multitenancy.enabled:true}")
    private boolean sqlMultitenancyEnabled;

    @Value("${tenant.multitenant.enabled:false}")
    private boolean tenantMultitenancyEnabled;

    @Value("${tenant.ids:}")
    private String tenantIds;

    @Value("${tenant.default:default}")
    private String defaultTenantId;

    /**
     * Initializes system properties for multitenancy configuration.
     * This method is called after dependency injection to set system properties
     * that are read by the sql-dao library for tenant-based data source routing.
     * Sets multi.tenant.ids based on whether multitenancy is enabled or disabled.
     */
    @PostConstruct
    public void init() {
        // Set the system property so that sql-dao's TenantRoutingDataSource can read it
        System.setProperty("multitenancy.enabled", String.valueOf(sqlMultitenancyEnabled));
        if (tenantMultitenancyEnabled) {
            System.setProperty("multi.tenant.ids", tenantIds);
        } else {
            System.setProperty("multi.tenant.ids", defaultTenantId);
        }
    }
}
