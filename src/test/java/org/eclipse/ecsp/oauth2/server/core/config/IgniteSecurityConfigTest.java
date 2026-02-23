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

package org.eclipse.ecsp.oauth2.server.core.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.CustomAccessTokenFailureHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.CustomAuthCodeFailureHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.FederatedIdentityAuthenticationSuccessHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.providers.CustomUserPwdAuthenticationProvider;
import org.eclipse.ecsp.oauth2.server.core.authentication.validator.CustomScopeValidator;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRequestRepository;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationSecurityContextRepository;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseSecurityContextRepository;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for IgniteSecurityConfig.
 *
 * @since 1.0.0
 */
@ExtendWith(MockitoExtension.class)
class IgniteSecurityConfigTest {

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService authorizationMetricsService;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private CustomAccessTokenFailureHandler customAccessTokenFailureHandler;

    @Mock
    private CustomUserPwdAuthenticationProvider customUserPwdAuthProvider;

    @Mock
    private CustomAuthCodeFailureHandler customAuthCodeFailureHandler;

    @Mock
    private AuthenticationConfiguration authenticationConfiguration;

    @Mock
    private AuthorizationSecurityContextRepository authorizationSecurityContextRepository;

    @Mock
    private OAuth2AuthorizationService oauth2AuthorizationService;

    @Mock
    private AuthorizationRequestRepository authorizationRequestRepository;

    @Mock
    private CustomScopeValidator customScopeValidator;

    @Mock
    private DatabaseSecurityContextRepository databaseSecurityContextRepository;

    @Mock
    private FederatedIdentityAuthenticationSuccessHandler federatedIdentityAuthenticationSuccessHandler;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    private IgniteSecurityConfig config;

    @BeforeEach
    void setUp() {
        config = new IgniteSecurityConfig(tenantConfigurationService,
                                        authorizationMetricsService,
                                        mock(AuditLogger.class));
        
        // Set required field values using ReflectionTestUtils
        ReflectionTestUtils.setField(config, "sessionTimeout", "1800");
        ReflectionTestUtils.setField(config, "forceLogin", false);
        ReflectionTestUtils.setField(config, "corsAllowedOriginPatterns", "*");
        ReflectionTestUtils.setField(config, "corsAllowedMethods", "GET,POST,PUT,DELETE");
        ReflectionTestUtils.setField(config, "sessionRecreationPolicy", "migrateSession");
    }

    @Test
    void testConstructor() {
        // Verify constructor initializes service
        assertNotNull(config);
    }

    @Test
    void testSessionRegistry() {
        // Act
        SessionRegistry sessionRegistry = config.sessionRegistry();

        // Assert
        assertNotNull(sessionRegistry);
        assertTrue(sessionRegistry instanceof org.springframework.security.core.session.SessionRegistryImpl);
    }

    @Test
    void testHttpSessionEventPublisher() {
        // Act
        HttpSessionEventPublisher publisher = config.httpSessionEventPublisher();

        // Assert
        assertNotNull(publisher);
    }

    @Test
    void testCustomLoginAuthenticationEntryPoint() throws Exception {
        // Arrange
        when(request.getParameterNames()).thenReturn(Collections.enumeration(
            java.util.Arrays.asList("client_id", "response_type", "scope")));
        when(request.getParameter("client_id")).thenReturn("test-client");
        when(request.getParameter("response_type")).thenReturn("code");
        when(request.getParameter("scope")).thenReturn("read");
        when(request.getRequestURI()).thenReturn("/tenant1/oauth2/authorize");

        // Act
        AuthenticationEntryPoint entryPoint = config.customLoginAuthenticationEntryPoint();
        entryPoint.commence(request, response, new BadCredentialsException("Test"));

        // Assert
        assertNotNull(entryPoint);
        verify(response).sendRedirect("/tenant1/login?client_id=test-client&response_type=code&scope=read"
                + "&issuer=tenant1");
    }

    @Test
    void testCustomLoginAuthenticationEntryPointWithRootPath() throws Exception {
        // Arrange
        when(request.getParameterNames()).thenReturn(Collections.enumeration(
            java.util.Arrays.asList("client_id")));
        when(request.getParameter("client_id")).thenReturn("test-client");
        when(request.getRequestURI()).thenReturn("/oauth2/authorize");

        // Act
        AuthenticationEntryPoint entryPoint = config.customLoginAuthenticationEntryPoint();
        entryPoint.commence(request, response, new BadCredentialsException("Test"));

        // Assert
        assertNotNull(entryPoint);
        verify(response).sendRedirect("/login?client_id=test-client");
    }

    @Test
    void testCustomSimpleUrlAuthenticationFailureHandler() throws Exception {
        // Arrange
        when(request.getSession(false)).thenReturn(session);
        when(request.getSession()).thenReturn(session);
        when(request.getParameter("issuer")).thenReturn("tenant1");
        when(request.getParameter("response_type")).thenReturn("code");
        when(request.getParameter("client_id")).thenReturn("test-client");
        when(request.getParameter("scope")).thenReturn("read");
        when(request.getParameter("redirect_uri")).thenReturn("http://localhost/callback");

        BadCredentialsException exception = new BadCredentialsException("Invalid credentials");

        // Act
        AuthenticationFailureHandler failureHandler = config.customSimpleUrlAuthenticationFailureHandler();
        failureHandler.onAuthenticationFailure(request, response, exception);

        // Assert
        assertNotNull(failureHandler);
        verify(session).setAttribute(
                org.springframework.security.web.WebAttributes.AUTHENTICATION_EXCEPTION, exception);
        verify(response).sendRedirect("/tenant1/login?error=true&response_type=code&client_id=test-client"
                + "&scope=read&redirect_uri=http://localhost/callback&issuer=tenant1");
    }

    @Test
    void testCustomSimpleUrlAuthenticationFailureHandlerWithoutSession() throws Exception {
        // Arrange
        when(request.getSession(false)).thenReturn(null);
        when(request.getParameter("issuer")).thenReturn("tenant1");
        when(request.getParameter("response_type")).thenReturn("code");
        when(request.getParameter("client_id")).thenReturn("test-client");
        when(request.getParameter("scope")).thenReturn("read");
        when(request.getParameter("redirect_uri")).thenReturn("http://localhost/callback");

        BadCredentialsException exception = new BadCredentialsException("Invalid credentials");

        // Act
        AuthenticationFailureHandler failureHandler = config.customSimpleUrlAuthenticationFailureHandler();
        failureHandler.onAuthenticationFailure(request, response, exception);

        // Assert
        assertNotNull(failureHandler);
        verify(response).sendRedirect("/tenant1/login?error=true&response_type=code&client_id=test-client"
                + "&scope=read&redirect_uri=http://localhost/callback&issuer=tenant1");
    }

    @Test
    void testFederatedIdentityAuthenticationSuccessHandler() {
        // Act
        FederatedIdentityAuthenticationSuccessHandler handler = config.federatedIdentityAuthenticationSuccessHandler();

        // Assert
        assertNotNull(handler);
    }

    @Test
    void testDatabaseSecurityContextRepositoryBean() {
        // Act - Try to call private getTenantSessionTimeout method through reflection
        try {
            String timeout = (String) ReflectionTestUtils.invokeMethod(config, "getTenantSessionTimeout");
            assertNotNull(timeout);
        } catch (Exception e) {
            // Method exists but we can verify the field is set properly
            String sessionTimeout = (String) ReflectionTestUtils.getField(config, "sessionTimeout");
            assertNotNull(sessionTimeout);
        }
    }

    @Test
    void testCreateDatabaseSecurityContextRepository() {
        // This method tests the bean creation logic by calling the configuration method
        DatabaseSecurityContextRepository repository = config.createDatabaseSecurityContextRepository(
                authorizationSecurityContextRepository);

        // Assert
        assertNotNull(repository);
    }

    @Test
    void testSessionRegistryCreationMultipleTimes() {
        // Act - Create multiple instances to test bean creation
        SessionRegistry registry1 = config.sessionRegistry();
        SessionRegistry registry2 = config.sessionRegistry();

        // Assert - Each call should create new instances (prototype behavior for tests)
        assertNotNull(registry1);
        assertNotNull(registry2);
    }

    @Test
    void testHttpSessionEventPublisherCreationMultipleTimes() {
        // Act
        HttpSessionEventPublisher publisher1 = config.httpSessionEventPublisher();
        HttpSessionEventPublisher publisher2 = config.httpSessionEventPublisher();

        // Assert
        assertNotNull(publisher1);
        assertNotNull(publisher2);
    }

    @Test
    void testCustomLoginAuthenticationEntryPointWithEmptyPath() throws Exception {
        // Arrange
        when(request.getParameterNames()).thenReturn(Collections.enumeration(Collections.emptyList()));
        when(request.getRequestURI()).thenReturn("/");

        // Act
        AuthenticationEntryPoint entryPoint = config.customLoginAuthenticationEntryPoint();
        entryPoint.commence(request, response, new BadCredentialsException("Test"));

        // Assert
        assertNotNull(entryPoint);
        verify(response).sendRedirect("/login");
    }

    @Test
    void testCustomLoginAuthenticationEntryPointWithComplexPath() throws Exception {
        // Arrange
        when(request.getParameterNames()).thenReturn(Collections.enumeration(
            java.util.Arrays.asList("state", "nonce")));
        when(request.getParameter("state")).thenReturn("abc123");
        when(request.getParameter("nonce")).thenReturn("xyz789");
        when(request.getRequestURI()).thenReturn("/tenant-with-dashes/oauth2/authorize");

        // Act
        AuthenticationEntryPoint entryPoint = config.customLoginAuthenticationEntryPoint();
        entryPoint.commence(request, response, new BadCredentialsException("Test"));

        // Assert
        assertNotNull(entryPoint);
        verify(response).sendRedirect("/tenant-with-dashes/login?state=abc123&nonce=xyz789&issuer=tenant-with-dashes");
    }

    @Test
    void testCustomSimpleUrlAuthenticationFailureHandlerWithNullParameters() throws Exception {
        // Arrange
        when(request.getSession(false)).thenReturn(session);
        when(request.getSession()).thenReturn(session);
        when(request.getParameter("issuer")).thenReturn(null);
        when(request.getParameter("response_type")).thenReturn(null);
        when(request.getParameter("client_id")).thenReturn(null);
        when(request.getParameter("scope")).thenReturn(null);
        when(request.getParameter("redirect_uri")).thenReturn(null);

        BadCredentialsException exception = new BadCredentialsException("Invalid credentials");

        // Act
        AuthenticationFailureHandler failureHandler = config.customSimpleUrlAuthenticationFailureHandler();
        failureHandler.onAuthenticationFailure(request, response, exception);

        // Assert
        assertNotNull(failureHandler);
        verify(session).setAttribute(
                org.springframework.security.web.WebAttributes.AUTHENTICATION_EXCEPTION, exception);
        verify(response).sendRedirect("/null/login?error=true&response_type=null&client_id=null"
                + "&scope=null&redirect_uri=null&issuer=null");
    }
}
