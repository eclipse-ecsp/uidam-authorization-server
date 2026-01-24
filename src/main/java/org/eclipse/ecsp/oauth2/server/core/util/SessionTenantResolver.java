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

package org.eclipse.ecsp.oauth2.server.core.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.sql.multitenancy.TenantContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Utility class for resolving tenant information from multiple sources
 * with session-based persistence across multi-threaded OAuth2 flows.
 * This resolver addresses the issue where different threads handle
 * different parts of the OAuth2 authorization flow, making ThreadLocal
 * tenant context unreliable.
 */
public class SessionTenantResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(SessionTenantResolver.class);
    
    private static final String TENANT_SESSION_KEY = "RESOLVED_TENANT_ID";

    private SessionTenantResolver() {
        // Utility class - prevent instantiation
    }

    /**
     * Get the current tenant ID with session-based fallback.
     * This method provides a more reliable tenant resolution than pure ThreadLocal
     * in multi-threaded environments like OAuth2 authorization flows.
     * Resolution order:
     * 1. ThreadLocal context (current thread) - fast path, no synchronization
     * 2. HTTP session (cross-thread persistence) - synchronized access
     * 3. null if no tenant found
     *
     * <p>Note: Intentionally not synchronized for performance - uses selective synchronization
     * in getFromSessionSynchronized() only when needed.
     *
     * @return current tenant ID, or null if no tenant is resolved
     */
    @SuppressWarnings("java:S2886") // Intentional selective synchronization for performance
    public static String getCurrentTenant() {
        // Fast path - no synchronization for ThreadLocal hits (majority of calls)
        String tenant = TenantContext.getCurrentTenant();
        
        if (StringUtils.hasText(tenant)) {
            LOGGER.debug("Tenant resolved from ThreadLocal: {}", tenant);
            return tenant;
        }

        // Slow path - synchronized only when ThreadLocal is empty
        return getFromSessionSynchronized();
    }

    /**
     * Synchronized session access - only called when ThreadLocal is empty.
     */
    private static synchronized String getFromSessionSynchronized() {
        // Double-check ThreadLocal inside lock (might have been set by another thread)
        String tenant = TenantContext.getCurrentTenant();
        if (StringUtils.hasText(tenant)) {
            LOGGER.debug("Tenant resolved from ThreadLocal after lock: {}", tenant);
            return tenant;
        }

        // Try to get from session if ThreadLocal is still empty
        tenant = getTenantFromSessionWithThreadLocalUpdate();
        if (StringUtils.hasText(tenant)) {
            LOGGER.debug("Tenant resolved from session: {}", tenant);
            return tenant;
        }
        
        LOGGER.debug("No tenant found in ThreadLocal or session");
        return null;
    }

    /**
     * Get tenant from session and update ThreadLocal if found.
     */
    private static String getTenantFromSessionWithThreadLocalUpdate() {
        try {
            String tenant = getTenantFromCurrentSession();
            if (StringUtils.hasText(tenant)) {
                // Update ThreadLocal for current thread with proper error handling
                updateThreadLocalSafely(tenant);
                return tenant;
            }
        } catch (IllegalStateException e) {
            LOGGER.debug("No request context available: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Safely update ThreadLocal with tenant, handling validation errors.
     */
    private static void updateThreadLocalSafely(String tenant) {
        try {
            TenantContext.setCurrentTenant(tenant);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Invalid tenant found in session: {}", tenant);
        }
    }

    /**
     * Set tenant ID in both ThreadLocal and session for persistence.
     * Uses synchronized access to prevent race conditions between ThreadLocal and session updates.
     *
     * @param tenantId the tenant ID to set
     * @throws IllegalArgumentException if tenantId is null or empty
     */
    public static synchronized void setCurrentTenant(String tenantId) {
        if (!StringUtils.hasText(tenantId)) {
            throw new IllegalArgumentException("Tenant ID cannot be null or empty");
        }

        // Set in ThreadLocal first - this will validate the tenant ID
        TenantContext.setCurrentTenant(tenantId);

        // Then store in session for cross-thread access
        storeTenantInCurrentSession(tenantId);
        LOGGER.debug("Tenant '{}' set in both ThreadLocal and session", tenantId);
    }

    /**
     * Get tenant from current HTTP session with cached request context.
     */
    private static String getTenantFromCurrentSession() {
        HttpServletRequest request = getCurrentRequest();
        if (request != null && request.getSession(false) != null) {
            try {
                return (String) request.getSession(false).getAttribute(TENANT_SESSION_KEY);
            } catch (ClassCastException e) {
                LOGGER.warn("Invalid tenant data type in session: {}", e.getMessage());
            }
        }
        return null;
    }

    /**
     * Store tenant in current HTTP session.
     */
    private static void storeTenantInCurrentSession(String tenantId) {
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request != null && StringUtils.hasText(tenantId)) {
                HttpSession session = request.getSession(true);
                session.setAttribute(TENANT_SESSION_KEY, tenantId);
            }
        } catch (IllegalStateException e) {
            LOGGER.warn("Cannot store tenant in session - no request context: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Cannot store tenant in session - invalid session: {}", e.getMessage());
        }
    }

    /**
     * Get current HTTP request from Spring's RequestContextHolder.
     */
    private static HttpServletRequest getCurrentRequest() {
        try {
            ServletRequestAttributes attributes = 
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            return attributes.getRequest();
        } catch (IllegalStateException e) {
            // No request context available (e.g., in background threads)
            return null;
        }
    }

    /**
     * Clear tenant from both ThreadLocal and session.
     */
    public static synchronized void clearTenant() {
        TenantContext.clear();
        
        try {
            HttpServletRequest request = getCurrentRequest();
            if (request != null && request.getSession(false) != null) {
                request.getSession(false).removeAttribute(TENANT_SESSION_KEY);
                LOGGER.debug("Cleared tenant from session");
            }
        } catch (IllegalStateException e) {
            LOGGER.warn("Cannot clear tenant from session - no request context: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            LOGGER.warn("Cannot clear tenant from session - invalid session: {}", e.getMessage());
        }
    }
}
