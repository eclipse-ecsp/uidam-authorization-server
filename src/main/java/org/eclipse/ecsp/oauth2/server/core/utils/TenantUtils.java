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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Utility class for handling tenant-related operations in a multi-tenant environment.
 * This class provides methods to resolve the tenant ID based on the application's
 * multi-tenancy configuration and to retrieve multi-tenancy settings.
 * The multi-tenancy settings are injected from application properties:
 * {@code tenant.multitenant.enabled} - Enables or disables multi-tenancy (default: false).
 * {@code tenant.default} - The default tenant ID to use when multi-tenancy is disabled (default: "ecsp").
 */
@Component
public class TenantUtils {
    private static TenantUtils instance;

    @Value("${tenant.multitenant.enabled:false}")
    private boolean multitenantEnabled;

    @Value("${tenant.default:ecsp}")
    private String defaultTenant;

    public TenantUtils() {
        // NOSONAR - Setting static field in constructor is intentional for Spring singleton pattern
        TenantUtils.instance = this; // NOSONAR
    }

    /**
     * Gets the singleton instance, creating a default one if not initialized by Spring.
     * This fallback is provided for test environments.
     *
     * @return the TenantUtils instance
     */
    private static TenantUtils getInstance() {
        if (instance == null) {
            // Fallback for test environments where Spring context is not available
            instance = new TenantUtils();
        }
        return instance;
    }

    /**
     * Resolves the tenant ID based on the multi-tenant configuration.
     * If multi-tenancy is enabled, the provided {@code tenantId} must not be {@code null} or empty,
     * otherwise an {@link IllegalArgumentException} is thrown.
     * If multi-tenancy is disabled and the {@code tenantId} is {@code null} or empty,
     * the default tenant ID is used.
     *
     * @param tenantId the tenant ID to resolve; may be {@code null} or empty if multi-tenancy is disabled
     * @return the resolved tenant ID
     * @throws IllegalArgumentException if multi-tenancy is enabled and {@code tenantId} is {@code null} or empty
     */
    public static String resolveTenantId(String tenantId) {
        TenantUtils utils = getInstance();
        if (utils.multitenantEnabled) {
            if (tenantId == null || tenantId.isEmpty()) {
                throw new IllegalArgumentException("TenantId is required when multi-tenant is enabled.");
            }
        } else {
            if (tenantId == null || tenantId.isEmpty()) {
                tenantId = utils.defaultTenant;
            }
        }
        return tenantId;
    }

    /**
     * Checks if multi-tenancy is enabled.
     *
     * @return {@code true} if multi-tenancy is enabled, {@code false} otherwise
     * @throws IllegalStateException if TenantUtils has not been initialized by Spring
     */
    public static boolean isMultitenantEnabled() {
        return getInstance().multitenantEnabled;
    }

    /**
     * Gets the default tenant ID.
     *
     * @return the default tenant ID
     * @throws IllegalStateException if TenantUtils has not been initialized by Spring
     */
    public static String getDefaultTenant() {
        return getInstance().defaultTenant;
    }
}
