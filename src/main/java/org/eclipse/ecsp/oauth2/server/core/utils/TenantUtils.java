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
    private static boolean multitenantEnabled;
    private static String defaultTenant;

    @Value("${tenant.multitenant.enabled:false}")
    public void setMultitenantEnabled(boolean enabled) {
        TenantUtils.multitenantEnabled = enabled;
    }

    @Value("${tenant.default:ecsp}")
    public void setDefaultTenant(String tenant) {
        TenantUtils.defaultTenant = tenant;
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
        if (multitenantEnabled) {
            if (tenantId == null || tenantId.isEmpty()) {
                throw new IllegalArgumentException("TenantId is required when multi-tenant is enabled.");
            }
        } else {
            if (tenantId == null || tenantId.isEmpty()) {
                tenantId = defaultTenant;
            }
        }
        return tenantId;
    }

    public static boolean isMultitenantEnabled() {
        return multitenantEnabled;
    }

    public static String getDefaultTenant() {
        return defaultTenant;
    }
}
