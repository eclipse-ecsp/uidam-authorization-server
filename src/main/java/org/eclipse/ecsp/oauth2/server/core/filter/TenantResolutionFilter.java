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

package org.eclipse.ecsp.oauth2.server.core.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * Filter to resolve and set the tenant context from HTTP request.
 * This filter runs early in the Spring Security filter chain, before OAuth2 processing.
 * It supports multiple tenant resolution strategies:
 * 1. X-Tenant-ID header
 * 2. Subdomain extraction
 * 3. Path-based tenant resolution
 * 4. Request parameter
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10) // Run early, but after basic security filters
public class TenantResolutionFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(TenantResolutionFilter.class);

    private static final String TENANT_HEADER = "X-Tenant-ID";
    private static final String TENANT_PARAM = "tenant";
    private static final int MIN_SUBDOMAIN_PARTS = 3;
    private static final int TENANT_PATH_INDEX = 2;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        LOGGER.info("Initializing TenantResolutionFilter");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String tenantId = null;

        try {
            // Strategy 1: Check X-Tenant-ID header
            tenantId = httpRequest.getHeader(TENANT_HEADER);
            if (StringUtils.hasText(tenantId)) {
                LOGGER.debug("Tenant resolved from header: {}", tenantId);
            } else {
                // Strategy 2: Extract from subdomain
                tenantId = extractTenantFromSubdomain(httpRequest);
                if (StringUtils.hasText(tenantId)) {
                    LOGGER.debug("Tenant resolved from subdomain: {}", tenantId);
                } else {
                    // Strategy 3: Extract from path
                    tenantId = extractTenantFromPath(httpRequest);
                    if (StringUtils.hasText(tenantId)) {
                        LOGGER.debug("Tenant resolved from path: {}", tenantId);
                    } else {
                        // Strategy 4: Check request parameter
                        tenantId = httpRequest.getParameter(TENANT_PARAM);
                        if (StringUtils.hasText(tenantId)) {
                            LOGGER.debug("Tenant resolved from parameter: {}", tenantId);
                        }
                    }
                }
            }

            // Set tenant context if resolved
            if (StringUtils.hasText(tenantId)) {
                TenantContext.setCurrentTenant(tenantId);
                LOGGER.info("Tenant context set to: {} for request: {}", tenantId, httpRequest.getRequestURI());
            } else {
                LOGGER.warn("No tenant could be resolved for request: {}", httpRequest.getRequestURI());
            }

            // Continue filter chain
            chain.doFilter(request, response);

        } finally {
            // Always clear tenant context after request processing
            TenantContext.clear();
            LOGGER.debug("Tenant context cleared for request: {}", httpRequest.getRequestURI());
        }
    }

    @Override
    public void destroy() {
        LOGGER.info("Destroying TenantResolutionFilter");
    }

    /**
     * Extract tenant from subdomain (e.g., ecsp.example.com -> ecsp).
     */
    private String extractTenantFromSubdomain(HttpServletRequest request) {
        String serverName = request.getServerName();
        if (StringUtils.hasText(serverName)) {
            String[] parts = serverName.split("\\.");
            if (parts.length >= MIN_SUBDOMAIN_PARTS) {
                // Return first part as tenant (subdomain)
                return parts[0];
            }
        }
        return null;
    }

    /**
     * Extract tenant from path (e.g., /tenant/ecsp/oauth2/authorize -> ecsp).
     */
    private String extractTenantFromPath(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (StringUtils.hasText(path) && path.startsWith("/tenant/")) {
            String[] parts = path.split("/");
            if (parts.length > TENANT_PATH_INDEX) {
                return parts[TENANT_PATH_INDEX]; // /tenant/{tenantId}/...
            }
        }
        return null;
    }
}
