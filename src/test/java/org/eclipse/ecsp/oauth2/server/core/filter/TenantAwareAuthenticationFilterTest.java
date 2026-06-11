/********************************************************************************
 * Copyright (c) 2023 - 2024 Harman International
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Test class for TenantAwareAuthenticationFilter.
 * Tests tenant-specific authentication method restrictions.
 */
@ExtendWith(MockitoExtension.class)
class TenantAwareAuthenticationFilterTest {

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private TenantProperties tenantProperties;

    private TenantAwareAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new TenantAwareAuthenticationFilter(tenantConfigurationService);
    }

    @Test
    void constructor_shouldCreateFilter() {
        // Assert
        assertNotNull(filter);
    }

    @Test
    void doFilterInternal_shouldContinueFilterChain_whenNonAuthEndpoint() throws ServletException, IOException {
        // Arrange
        when(request.getRequestURI()).thenReturn("/api/users");

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn("ecsp");

            // Act
            filter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain).doFilter(request, response);
            verifyNoInteractions(tenantConfigurationService);
        }
    }

    @Test
    void doFilterInternal_shouldContinueFilterChain_whenFormLoginAllowed() throws ServletException, IOException {
        // Arrange
        when(request.getRequestURI()).thenReturn("/login");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("username")).thenReturn("testuser");
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.isInternalLoginEnabled()).thenReturn(true);

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn("ecsp");

            // Act
            filter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain).doFilter(request, response);
            verify(tenantConfigurationService).getTenantProperties();
        }
    }

    @Test
    void doFilterInternal_shouldRedirect_whenFormLoginNotAllowed() throws ServletException, IOException {
        // Arrange
        when(request.getRequestURI()).thenReturn("/login");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("username")).thenReturn("testuser");
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.isInternalLoginEnabled()).thenReturn(false);

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn("ecsp");

            // Act
            filter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(response).sendRedirect(contains("error"));
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void doFilterInternal_shouldContinueFilterChain_whenOauthLoginAllowed() throws ServletException, IOException {
        // Arrange
        when(request.getRequestURI()).thenReturn("/oauth2/authorization/google");
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.isExternalIdpEnabled()).thenReturn(true);

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn("ecsp");

            // Act
            filter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain).doFilter(request, response);
            verify(tenantConfigurationService).getTenantProperties();
        }
    }

    @Test
    void doFilterInternal_shouldRedirect_whenOauthLoginNotAllowed() throws ServletException, IOException {
        // Arrange
        when(request.getRequestURI()).thenReturn("/oauth2/authorization/google");
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.isExternalIdpEnabled()).thenReturn(false);

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn("ecsp");

            // Act
            filter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(response).sendRedirect(contains("error"));
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void doFilterInternal_shouldRedirectToError_whenExceptionOccurs() throws ServletException, IOException {
        // Arrange
        when(request.getRequestURI()).thenReturn("/login");
        when(tenantConfigurationService.getTenantProperties()).thenThrow(new RuntimeException("Test exception"));

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn("ecsp");

            // Act
            filter.doFilterInternal(request, response, filterChain);

            // Assert - Should redirect to error page when authentication method check fails (fail-secure behavior)
            verify(response).sendRedirect(contains("error=no_auth_methods_available"));
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void doFilterInternal_shouldContinueFilterChain_whenNullTenantContext() throws ServletException, IOException {
        // Arrange
        when(request.getRequestURI()).thenReturn("/api/users");

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn(null);

            // Act
            filter.doFilterInternal(request, response, filterChain);

            // Assert
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void doFilterInternal_shouldContinueFilterChain_whenLoginGetRequest() throws ServletException, IOException {
        // GET to /login should pass-through (not a form login attempt since no username param needed)
        // For GET, isFormLoginAttempt=false, isOauthLoginAttempt=false → returns true → continue
        when(request.getRequestURI()).thenReturn("/login");
        when(request.getMethod()).thenReturn("GET");
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn("ecsp");

            // Act
            filter.doFilterInternal(request, response, filterChain);

            // Assert - should continue since it's GET (not a form login attempt)
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void doFilterInternal_shouldContinueFilterChain_whenLoginPostWithoutUsername()
            throws ServletException, IOException {
        // POST to /login but without username param - not a form login attempt
        when(request.getRequestURI()).thenReturn("/login");
        when(request.getMethod()).thenReturn("POST");
        when(request.getParameter("username")).thenReturn(null);
        when(tenantConfigurationService.getTenantProperties())
                .thenReturn(tenantProperties);

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn("ecsp");

            // Act
            filter.doFilterInternal(request, response, filterChain);

            // Assert - should continue since there's no username (not a form login attempt)
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void doFilterInternal_shouldRedirect_whenNullTenantProperties() throws ServletException, IOException {
        // When tenantProperties is null, isAuthenticationMethodAllowed returns false (fail-secure)
        // getMethod/getParameter NOT called in this code path (null check is first)
        when(request.getRequestURI()).thenReturn("/login");
        when(tenantConfigurationService.getTenantProperties()).thenReturn(null);

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn("ecsp");

            // Act
            filter.doFilterInternal(request, response, filterChain);

            // Assert - fail-secure: redirect to error
            verify(response).sendRedirect(contains("error"));
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void doFilterInternal_shouldRethrowServletException() throws ServletException, IOException {
        // Arrange
        when(request.getRequestURI()).thenReturn("/api/data");
        org.mockito.Mockito.doThrow(new ServletException("Test servlet error"))
            .when(filterChain).doFilter(request, response);

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn("ecsp");

            // Act & Assert - ServletException should be re-thrown
            org.junit.jupiter.api.Assertions.assertThrows(ServletException.class,
                () -> filter.doFilterInternal(request, response, filterChain));
        }
    }

    @Test
    void doFilterInternal_shouldContinueFilterChain_whenLoginEndpointButOauthStyle()
            throws ServletException, IOException {
        // URI contains "oauth2/authorization/" - it's an oauth login endpoint check
        when(request.getRequestURI()).thenReturn("/app/oauth2/authorization/google");
        when(tenantConfigurationService.getTenantProperties())
                .thenReturn(tenantProperties);
        when(tenantProperties.isExternalIdpEnabled()).thenReturn(true);

        try (MockedStatic<SessionTenantResolver> resolver = mockStatic(SessionTenantResolver.class)) {
            resolver.when(SessionTenantResolver::getCurrentTenant).thenReturn("ecsp");

            // Act
            filter.doFilterInternal(request, response, filterChain);

            // Assert - OAuth is enabled, should continue
            verify(filterChain).doFilter(request, response);
        }
    }
}
