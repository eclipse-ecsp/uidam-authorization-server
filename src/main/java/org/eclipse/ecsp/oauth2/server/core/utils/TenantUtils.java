package org.eclipse.ecsp.oauth2.server.core.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

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
