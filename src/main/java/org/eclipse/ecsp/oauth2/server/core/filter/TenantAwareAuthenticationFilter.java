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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.util.SessionTenantResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.IDP_AUTHORIZATION_URI;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_FAILURE_HANDLER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_HANDLER;
/**
 * Filter that enforces tenant-specific authentication method restrictions. This filter runs after
 * TenantResolutionFilter but before Spring Security authentication filters. It validates that the attempted
 * authentication method is allowed for the current tenant.
 * Multi-Thread Support: Uses SessionTenantResolver instead of direct TenantContext to handle multi-threaded OAuth2
 * flows where different threads may process different parts of the same user session.
 * Authentication Method Control: - Form login: Controlled by tenantProperties.isInternalLoginEnabled() - OAuth login:
 * Controlled by tenantProperties.isExternalIdpEnabled()
 * If a tenant doesn't support an authentication method, this filter redirects to an appropriate page.
 */

@Component 
@Order(100) // Run after TenantResolutionFilter (10) but before security filters (200+)
public class TenantAwareAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(TenantAwareAuthenticationFilter.class);

    private final TenantConfigurationService tenantConfigurationService;

    // Authentication endpoints to monitor - using actual codebase constants
    private static final String FORM_LOGIN_ENDPOINT = LOGIN_HANDLER; // "/login"
    private static final String OAUTH_LOGIN_ENDPOINT = IDP_AUTHORIZATION_URI; // "/oauth2/authorization/"
    private static final String ERROR_REDIRECT_PATH = LOGIN_FAILURE_HANDLER; // "/login?error"

    public TenantAwareAuthenticationFilter(TenantConfigurationService tenantConfigurationService) {
        this.tenantConfigurationService = tenantConfigurationService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestUri = request.getRequestURI();
        String currentTenant = SessionTenantResolver.getCurrentTenant();

        LOGGER.debug("Processing authentication filter for tenant: {} on URI: {}", currentTenant, requestUri);

        try {
            // Only check authentication-related endpoints
            if (isAuthenticationEndpoint(requestUri) && !isAuthenticationMethodAllowed(request)) {
                LOGGER.warn("Authentication method not allowed for tenant: {} on URI: {}", currentTenant, requestUri);
                redirectToAlternativeAuth(response);
                return;
            }

            // Continue filter chain if authentication method is allowed
            filterChain.doFilter(request, response);

        } catch (ServletException | IOException e) {
            // Re-throw servlet exceptions as they're part of the filter contract
            throw e;
        } catch (RuntimeException e) {
            LOGGER.error("Runtime error in tenant-aware authentication filter for tenant: {}", currentTenant, e);
            // Fail secure: redirect to error page instead of continuing
            response.sendRedirect(ERROR_REDIRECT_PATH + "?error=tenant_security_error");
        }
    }

    /**
     * Check if the current request is for an authentication endpoint.
     */
    private boolean isAuthenticationEndpoint(String requestUri) {
        return requestUri.startsWith(FORM_LOGIN_ENDPOINT) || requestUri.contains(OAUTH_LOGIN_ENDPOINT);
    }

    /**
     * Check if the attempted authentication method is allowed for the current tenant.
     */
    private boolean isAuthenticationMethodAllowed(HttpServletRequest request) {
        String requestUri = request.getRequestURI();

        try {
            TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
            
            // Fail secure: if no tenant properties found, deny authentication attempts
            if (tenantProperties == null) {
                LOGGER.warn("No tenant properties found for current tenant - denying authentication attempt");
                return false;
            }

            // Check form login attempts
            if (isFormLoginAttempt(request, requestUri)) {
                boolean allowed = tenantProperties.isInternalLoginEnabled();
                LOGGER.debug("Form login attempt for tenant: {} - allowed: {}",
                        SessionTenantResolver.getCurrentTenant(), allowed);
                return allowed;
            }

            // Check OAuth login attempts
            if (isOauthLoginAttempt(requestUri)) {
                boolean allowed = tenantProperties.isExternalIdpEnabled();
                LOGGER.debug("OAuth login attempt for tenant: {} - allowed: {}",
                        SessionTenantResolver.getCurrentTenant(), allowed);
                return allowed;
            }

            // Allow other requests by default (non-authentication endpoints)
            return true;

        } catch (RuntimeException e) {
            LOGGER.error("Runtime error checking authentication method for tenant: {}",
                    SessionTenantResolver.getCurrentTenant(), e);
            // Fail secure: deny authentication when configuration cannot be determined
            return false;
        }
    }

    /**
     * Check if this is a form login attempt.
     */
    private boolean isFormLoginAttempt(HttpServletRequest request, String requestUri) {
        // Form login POST to /login with username/password
        return "POST".equals(request.getMethod()) && FORM_LOGIN_ENDPOINT.equals(requestUri)
                && StringUtils.hasText(request.getParameter("username"));
    }

    /**
     * Check if this is an OAuth login attempt.
     */
    private boolean isOauthLoginAttempt(String requestUri) {
        return requestUri.startsWith(OAUTH_LOGIN_ENDPOINT) || requestUri.contains("/oauth2/authorization/");
    }

    /**
     * Redirect to alternative authentication method or error page.
     */
    private void redirectToAlternativeAuth(HttpServletResponse response)
            throws IOException {
        try {
            // No alternative available - show error
            LOGGER.warn("No authentication methods available for tenant: {}", SessionTenantResolver.getCurrentTenant());
            response.sendRedirect(ERROR_REDIRECT_PATH + "?error=no_auth_methods_available");

        } catch (Exception e) {
            LOGGER.error("Error redirecting for tenant: {}", SessionTenantResolver.getCurrentTenant(), e);
            response.sendRedirect(ERROR_REDIRECT_PATH + "?error=redirect_error");
        }
    }
}
