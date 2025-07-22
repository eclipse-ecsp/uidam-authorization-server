package org.eclipse.ecsp.oauth2.server.core.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.ECSP;

/**
 * TenantContext is a utility class that provides a way to manage the current tenant in a thread-local context. It
 * allows setting and getting the current tenant ID, which can be useful in multi-tenant applications.
 * Enhanced with proper cleanup and default tenant support.
 */
public class TenantContext {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(TenantContext.class);
    
    private TenantContext() {
        // Private constructor to prevent instantiation
    }

    private static final ThreadLocal<String> CURRENT_TENANT = new ThreadLocal<>();
    private static final String DEFAULT_TENANT_ID = ECSP;

    /**
     * Get the current tenant ID from thread local context.
     *
     * @return current tenant ID or default if not set
     */
    public static String getCurrentTenant() {
        String tenant = CURRENT_TENANT.get();
        if (tenant == null) {
            tenant = DEFAULT_TENANT_ID;
            LOGGER.debug("No tenant found in context, using default: {}", tenant);
        }
        return tenant;
    }

    /**
     * Set the current tenant ID in thread local context.
     *
     * @param tenant the tenant ID to set
     */
    public static void setCurrentTenant(String tenant) {
        if (tenant == null || tenant.trim().isEmpty()) {
            tenant = DEFAULT_TENANT_ID;
        }
        CURRENT_TENANT.set(tenant);
        LOGGER.debug("Set current tenant to: {}", tenant);
    }
    
    /**
     * Clear the current tenant from thread local context.
     * Should be called at the end of request processing to prevent memory leaks.
     */
    public static void clear() {
        String tenant = CURRENT_TENANT.get();
        CURRENT_TENANT.remove();
        LOGGER.debug("Cleared tenant context for: {}", tenant);
    }
    
    /**
     * Check if a tenant is currently set.
     *
     * @return true if tenant is set, false otherwise
     */
    public static boolean hasTenant() {
        return CURRENT_TENANT.get() != null;
    }
}