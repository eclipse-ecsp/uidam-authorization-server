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


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.eclipse.ecsp.oauth2.server.core.exception.TenantResolutionException;
import org.eclipse.ecsp.oauth2.server.core.response.BaseRepresentation;
import org.eclipse.ecsp.oauth2.server.core.response.ResponseMessage;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Filter to resolve and set the tenant context from HTTP request. This filter runs early in the Spring Security filter
 * chain, before OAuth2 processing. It supports multiple tenant resolution strategies: 
 * 1. tenantId header 
 * 2. Path-based tenant resolution (/tenant/{tenantId}/... or /{tenantId}/oauth2/...)
 * 3. Request parameter
 * Static resources (CSS, JS, images, etc.) are bypassed and served without tenant resolution.
 */
@Component 
@Order(Ordered.HIGHEST_PRECEDENCE + 10) // Run early, but after basic security filters
public class TenantResolutionFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(TenantResolutionFilter.class);
    
    private final TenantConfigurationService tenantConfigurationService;
    
    // Static resource patterns to bypass tenant resolution (includes standalone /favicon.ico)
    private static final Pattern STATIC_RESOURCE_PATTERN =
        Pattern.compile("^/(actuator|css|js|images|fonts|favicon\\.ico|static)(/.*)?$", Pattern.CASE_INSENSITIVE);
    
    // Path parsing constants
    private static final int MIN_PATH_PARTS_FOR_TENANT = 3;
    private static final int TENANT_ID_POSITION = 2;
    private static final int TENANT_PREFIX_POSITION = 1;

    private static final String TENANT_HEADER = "tenantId";
    private static final String TENANT_PARAM = "tenant";
    private static final String TENANT_SESSION_KEY = "RESOLVED_TENANT_ID";
    
    // Whitelist of path segments that should trigger tenant resolution
    private static final Set<String> TENANT_AWARE_PATHS = Set.of(
        "oauth2",           // /{tenant}/oauth2/authorize, /{tenant}/oauth2/token, etc.
        "login",            // /{tenant}/login
        "revoke",           // /{tenant}/revoke/revokeByAdmin
        "recovery",         // /{tenant}/recovery/**
        ".well-known",      // /{tenant}/.well-known/openid-configuration
        "jwks",             // /{tenant}/jwks
        "userinfo",         // /{tenant}/userinfo
        "authorize",        // /{tenant}/authorize (direct)
        "token",            // /{tenant}/token (direct)
        "introspect"        // /{tenant}/introspect (direct)
    );
    
    // Blacklist of path segments that should NOT be considered as tenant IDs
    private static final Set<String> INVALID_TENANT_IDS = Set.of(
        "api", "v1", "v2", "public", "health", "actuator", "admin", "management",
        "oauth2", "login", "authorize", "token", "introspect", "revoke", 
        "userinfo", "jwks", ".well-known", TENANT_PARAM
    );

    /**
     * Constructor to inject dependencies.
     *
     * @param tenantConfigurationService the tenant configuration service
     */
    public TenantResolutionFilter(TenantConfigurationService tenantConfigurationService) {
        this.tenantConfigurationService = tenantConfigurationService;
    }

    @Value("${tenant.multitenant.enabled}")
    private boolean multiTenantEnabled;

    @Value("${tenant.default}")
    private String defaultTenant;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        LOGGER.info("Initializing TenantResolutionFilter");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String requestUri = httpRequest.getRequestURI();
        
        // Skip tenant resolution for static resources (including /favicon.ico)
        if (isStaticResource(requestUri)) {
            LOGGER.debug("Skipping tenant resolution for static resource: {}", requestUri);
            chain.doFilter(request, response);
            return;
        }
        
        String tenantId = null;
        
        LOGGER.debug("Processing tenant resolution for request: {}", requestUri);

        try {
            // First, try to resolve tenant from request (path, header, parameter)
            tenantId = resolveTenantFromRequest(httpRequest);
            if (StringUtils.hasText(tenantId)) {
                LOGGER.debug("Tenant resolved from request: {}", tenantId);
            } else {
                // Fallback: try to get tenant from session
                //tenantId = getTenantFromSession(httpRequest);
                if (StringUtils.hasText(tenantId)) {
                    LOGGER.debug("Tenant resolved from session: {}", tenantId);
                } else if (multiTenantEnabled) {
                    // No tenant could be resolved - throw exception
                    LOGGER.error("No tenant could be resolved for request: {}", requestUri);
                    throw TenantResolutionException.tenantNotFoundInRequest(requestUri);
                }
            }

            // Additional validation: if multitenant is disabled, set tenantId to default
            if (!StringUtils.hasText(tenantId) && !multiTenantEnabled) {
                tenantId = defaultTenant;
                LOGGER.debug("Multitenant disabled, setting tenantId to default: {}", tenantId);
            }

            // Validate that the resolved tenant actually exists in configuration
            if (!isValidConfiguredTenant(tenantId)) {
                LOGGER.error("Tenant is not configured in the system for request: {}", requestUri);
                throw TenantResolutionException.invalidTenant(tenantId, requestUri);
            }
            
            // Set tenant context
            TenantContext.setCurrentTenant(tenantId);
            MDC.put(TENANT_HEADER, tenantId);
            LOGGER.debug("Tenant '{}' validated and set in context", tenantId);
            
            // Continue filter chain
            chain.doFilter(request, response);

        } catch (TenantResolutionException ex) {
            // Handle tenant resolution exceptions and return proper error response
            LOGGER.error("Tenant resolution failed: {}", ex.getMessage(), ex);
            handleTenantResolutionException(httpResponse, ex);
            
        } finally {
            // Always clear tenant context after request processing
            TenantContext.clear();
            LOGGER.debug("Tenant context cleared for request: {}", requestUri);
            MDC.remove(TENANT_HEADER);
        }
    }

    @Override
    public void destroy() {
        LOGGER.info("Destroying TenantResolutionFilter");
    }

    /**
     * Check if the request URI is for a static resource that should bypass tenant resolution.
     *
     * @param requestUri The request URI to check
     * @return true if the URI matches static resource patterns
     */
    private boolean isStaticResource(String requestUri) {
        if (!StringUtils.hasText(requestUri)) {
            return false;
        }
        
        boolean isStatic = STATIC_RESOURCE_PATTERN.matcher(requestUri).matches();
        if (isStatic) {
            LOGGER.debug("Request URI '{}' identified as static resource", requestUri);
        }
        return isStatic;
    }

    /**
     * Get tenant ID from HTTP session.
     */
    private String getTenantFromSession(HttpServletRequest request) {
        if (request.getSession(false) != null) {
            return (String) request.getSession(false).getAttribute(TENANT_SESSION_KEY);
        }
        return null;
    }

    /**
     * Store tenant ID in HTTP session.
     */
    private void storeTenantInSession(HttpServletRequest request, String tenantId) {
        if (StringUtils.hasText(tenantId)) {
            request.getSession(true).setAttribute(TENANT_SESSION_KEY, tenantId);
            LOGGER.debug("Stored tenant '{}' in session for future requests", tenantId);
        }
    }

    private String resolveTenantFromRequest(HttpServletRequest request) {
        String tenantId = null;

        // Strategy 1: Check header
        tenantId = request.getHeader(TENANT_HEADER);
        if (StringUtils.hasText(tenantId)) {
            LOGGER.debug("Tenant resolved from header: {}", tenantId);
            storeTenantInSession(request, tenantId);
            return tenantId;
        }

        // Strategy 2: Extract from path (/{tenantId}/oauth2/...)
        tenantId = extractTenantFromPathPrefix(request);
        if (StringUtils.hasText(tenantId)) {
            LOGGER.debug("Tenant resolved from path prefix: {}", tenantId);
            storeTenantInSession(request, tenantId);
            return tenantId;
        }

        // Strategy 3: Generic path prefix (/{tenantId}/...) - fallback when whitelist misses
        String path = request.getRequestURI();
        if (path != null) {
            String[] genericParts = path.split("/");
            if (genericParts.length > 1) {
                String genericTenant = genericParts[1];
                if (isValidTenantId(genericTenant)) {
                    LOGGER.debug("Extracted tenant '{}' from generic path prefix: {}", genericTenant, path);
                    storeTenantInSession(request, genericTenant);
                    return genericTenant;
                }
            }
        }
        // Strategy 4: Check request parameter tenantId
        tenantId = request.getParameter(TENANT_HEADER);
        if (StringUtils.hasText(tenantId)) {
            LOGGER.debug("Tenant resolved from parameter: {}", tenantId);
            storeTenantInSession(request, tenantId);
            return tenantId;
        }

        return null;
    }

    /**
     * Extract tenant from path if present. Uses a whitelist approach to identify tenant-aware endpoints.
     * Supports patterns for OAuth2, authentication, and discovery endpoints:
     * 1. /tenant/{tenantId}/... → {tenantId} (explicit tenant prefix)
     * 2. /{tenantId}/{whitelisted-path}/... → {tenantId} (tenant-aware endpoints)
     * 
     * <p>Whitelisted paths include:
     * - oauth2: /{tenant}/oauth2/authorize, /{tenant}/oauth2/token, etc.
     * - login: /{tenant}/login
     * - .well-known: /{tenant}/.well-known/openid-configuration
     * - jwks, userinfo, authorize, token, introspect, revoke
     * 
     * <p>Examples:
     * - /demo/.well-known/openid-configuration → demo
     * - /ecsp/oauth2/authorize → ecsp
     * - /tenant/demo/oauth2/token → demo
     * - /api/v1/oauth2/authorize → null (api/v1 excluded)
     */
    private String extractTenantFromPathPrefix(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (!StringUtils.hasText(path)) {
            return null;
        }
        
        String[] parts = path.split("/");
        if (parts.length < MIN_PATH_PARTS_FOR_TENANT) {
            return null;
        }
        
        // Pattern 1: /{tenantId}/... (explicit tenant prefix)
        if (TENANT_PARAM.equals(parts[TENANT_PREFIX_POSITION])) {
            String tenantId = parts[TENANT_ID_POSITION];
            if (StringUtils.hasText(tenantId)) {
                LOGGER.debug("Extracted tenant '{}' from explicit tenant path: {}", tenantId, path);
                return tenantId;
            }
        }
        
        // Pattern 2: /{tenantId}/{whitelisted-path}/... (tenant-aware endpoints)
        String secondLevelPath = parts[TENANT_ID_POSITION];
        if (TENANT_AWARE_PATHS.contains(secondLevelPath)) {
            String tenantId = parts[TENANT_PREFIX_POSITION];
            if (isValidTenantId(tenantId)) {
                LOGGER.debug("Extracted tenant '{}' from whitelisted path '{}': {}", 
                    tenantId, secondLevelPath, path);
                return tenantId;
            }
        }
        
        return null;
    }
    
    /**
     * Validates if the extracted string is a valid tenant ID by excluding common non-tenant path segments.
     */
    private boolean isValidTenantId(String tenantId) {
        return StringUtils.hasText(tenantId) && !INVALID_TENANT_IDS.contains(tenantId);
    }

    /**
     * Validates if the resolved tenant actually exists in the system configuration.
     *
     * @param tenantId the tenant ID to validate
     * @return true if the tenant exists in configuration, false otherwise
     */
    private boolean isValidConfiguredTenant(String tenantId) {
        if (!StringUtils.hasText(tenantId)) {
            return false;
        }
        
        try {
            boolean exists = tenantConfigurationService.tenantExists(tenantId);
            LOGGER.debug("Tenant '{}' exists in configuration: {}", tenantId, exists);
            return exists;
        } catch (Exception e) {
            LOGGER.error("Error validating tenant '{}': {}", tenantId, e.getMessage());
            return false;
        }
    }

    /**
     * Handles TenantResolutionException by writing a proper JSON error response.
     *
     * @param response the HTTP response
     * @param ex the TenantResolutionException
     * @throws IOException if writing response fails
     */
    private void handleTenantResolutionException(HttpServletResponse response, TenantResolutionException ex) 
            throws IOException {

        // Create response message using exception key and parameters
        ResponseMessage errorResponse = new ResponseMessage(ex.getKey(), (Object[]) ex.getParameters());
        BaseRepresentation baseRepresentation = new BaseRepresentation();
        baseRepresentation.addMessage(errorResponse);

        // Use the HTTP status from the exception (defaults to BAD_REQUEST)
        HttpStatus status = ex.getHttpStatus() != null ? ex.getHttpStatus() : HttpStatus.BAD_REQUEST;

        // Set response headers
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // Write JSON response
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(baseRepresentation);
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }

}
