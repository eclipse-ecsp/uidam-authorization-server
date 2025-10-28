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
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


/**
 * Test class for TenantResolutionFilter.
 * Tests all tenant resolution strategies and edge cases.
 */
@ExtendWith(MockitoExtension.class)
class TenantResolutionFilterTest {

    private static final String TENANT_NOT_FOUND_ERROR = "TENANT_NOT_FOUND_IN_REQUEST";

    private TenantResolutionFilter tenantResolutionFilter;

    @Mock
    private FilterChain filterChain;

    @Mock
    private FilterConfig filterConfig;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        tenantResolutionFilter = new TenantResolutionFilter(tenantConfigurationService);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        // Set default property values for @Value fields
        setSpringProperties(true, "ecsp");
    }

    @AfterEach
    void tearDown() {
        // Ensure tenant context is cleared after each test
        TenantContext.clear();
    }

    private void setSpringProperties(boolean multiTenantEnabled, String defaultTenant) {
        // Simulate Spring @Value injection for test
        try {
            java.lang.reflect.Field multiTenantField = TenantResolutionFilter.class
                .getDeclaredField("multiTenantEnabled");
            multiTenantField.setAccessible(true);
            multiTenantField.set(tenantResolutionFilter, multiTenantEnabled);
            java.lang.reflect.Field defaultTenantField = TenantResolutionFilter.class.getDeclaredField("defaultTenant");
            defaultTenantField.setAccessible(true);
            defaultTenantField.set(tenantResolutionFilter, defaultTenant);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Helper method to verify error response for tenant resolution failures.
     */
    private void assertTenantNotFoundErrorResponse() {
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());
        
        try {
            String responseContent = response.getContentAsString();
            assertTrue(responseContent.contains(TENANT_NOT_FOUND_ERROR));
        } catch (Exception e) {
            throw new AssertionError("Failed to get response content", e);
        }
    }

    @Test
    void initShouldCompleteWithoutException() {
        // Test that init method completes without exception
        assertDoesNotThrow(() -> tenantResolutionFilter.init(filterConfig));
    }

    @Test
    void destroyShouldCompleteWithoutException() {
        // Test that destroy method completes without exception
        assertDoesNotThrow(() -> tenantResolutionFilter.destroy());
    }

    @Test
    void tenantResolutionFromHeaderShouldSetTenantContext() throws IOException, ServletException {
        // Given
        request.addHeader("tenantId", "test-tenant");
        request.setRequestURI("/oauth2/authorize");
        when(tenantConfigurationService.tenantExists("test-tenant")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("test-tenant"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void tenantResolutionFromPathShouldExtractTenantFromPath() throws IOException, ServletException {
        // Given
        request.setRequestURI("/tenant/ecsp/oauth2/authorize");
        when(tenantConfigurationService.tenantExists("ecsp")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("ecsp"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void tenantResolutionFromParameterShouldExtractTenantFromParameter() throws IOException, ServletException {
        // Given
        request.addParameter("tenantId", "param-tenant");
        request.setRequestURI("/oauth2/authorize");
        when(tenantConfigurationService.tenantExists("param-tenant")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("param-tenant"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void tenantResolutionPriorityShouldPreferHeaderOverOtherSources() throws IOException, ServletException {
        // Given - Set all possible tenant sources
        request.addHeader("tenantId", "header-tenant");
        request.setRequestURI("/tenant/path-tenant/oauth2/authorize");
        request.addParameter("tenantId", "param-tenant");
        when(tenantConfigurationService.tenantExists("header-tenant")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Header should take priority
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("header-tenant"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void noTenantResolvedShouldNotSetTenantContext() throws IOException, ServletException {
        // Given - No tenant information in request
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When - Should return error response for no valid tenant
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should return error response instead of proceeding
            assertTenantNotFoundErrorResponse();

            // Verify tenant context was cleared
            tenantContextMock.verify(TenantContext::clear);
            // Filter chain should not be called due to error response
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void emptyTenantHeaderShouldBeIgnored() throws IOException, ServletException {
        // Given
        request.addHeader("tenantId", "");
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When - Should return error response for empty header (no valid tenant)
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should return error response instead of proceeding
            assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
            assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());
            
            String responseContent = response.getContentAsString();
            assertTrue(responseContent.contains("TENANT_NOT_FOUND_IN_REQUEST"));

            // Verify tenant context was cleared
            tenantContextMock.verify(TenantContext::clear);
            // Filter chain should not be called due to exception
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void nullTenantHeaderShouldBeIgnored() throws IOException, ServletException {
        // Given - No header is added (simulating null header)
        tenantValidation("/oauth2/authorize");
    }

    private void tenantValidation(String requestUri)
            throws IOException, ServletException {
        request.setRequestURI(requestUri);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should return error response instead of proceeding
            assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
            assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());
            
            String responseContent = response.getContentAsString();
            assertTrue(responseContent.contains("TENANT_NOT_FOUND_IN_REQUEST"));

            // Verify tenant context was cleared
            tenantContextMock.verify(TenantContext::clear);
            // Filter chain should not be called due to exception
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void whitespaceOnlyTenantHeaderShouldBeIgnored() throws IOException, ServletException {
        // Given
        request.addHeader("tenantId", "   ");
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should return error response instead of proceeding
            assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
            assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());
            
            String responseContent = response.getContentAsString();
            assertTrue(responseContent.contains("TENANT_NOT_FOUND_IN_REQUEST"));

            // Verify tenant context was cleared
            tenantContextMock.verify(TenantContext::clear);
            // Filter chain should not be called due to exception
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void pathExtractionWithInvalidPathShouldBeIgnored() throws IOException, ServletException {
        
        tenantValidation("/tenant/");
        
    }

    @Test
    void pathExtractionWithShortPathShouldBeIgnored() throws IOException, ServletException {
        // Given
        tenantValidation("/tenant");
        
    }

    @Test
    void pathExtractionWithNonTenantPathShouldBeIgnored() throws IOException, ServletException {
        // Given
        tenantValidation("/api/v1/oauth2/authorize");
    }

    @Test
    void pathExtractionWithEmptyPathShouldBeIgnored() throws IOException, ServletException {
        // Given
        tenantValidation("");
    }

    @Test
    void pathExtractionWithNullPathShouldBeIgnored() throws IOException, ServletException {
        // Given
        request.setRequestURI(null);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should return error response instead of proceeding
            assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
            assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());
            
            String responseContent = response.getContentAsString();
            assertTrue(responseContent.contains("TENANT_NOT_FOUND_IN_REQUEST"));

            // Verify tenant context was cleared
            tenantContextMock.verify(TenantContext::clear);
            // Filter chain should not be called due to exception
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void parameterExtractionWithEmptyParameterShouldBeIgnored() throws IOException, ServletException {
        // Given
        request.addParameter("tenantId", "");
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should return error response instead of proceeding
            assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
            assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());
            
            String responseContent = response.getContentAsString();
            assertTrue(responseContent.contains("TENANT_NOT_FOUND_IN_REQUEST"));

            // Verify tenant context was cleared
            tenantContextMock.verify(TenantContext::clear);
            // Filter chain should not be called due to exception
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void parameterExtractionWithNullParameterShouldBeIgnored() throws IOException, ServletException {
        // Given
        request.addParameter("tenantId", (String) null);
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should return error response instead of proceeding
            assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
            assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());
            
            String responseContent = response.getContentAsString();
            assertTrue(responseContent.contains("TENANT_NOT_FOUND_IN_REQUEST"));

            // Verify tenant context was cleared
            tenantContextMock.verify(TenantContext::clear);
            // Filter chain should not be called due to exception
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void tenantContextAlwaysClearedShouldEnsureCleanup() throws IOException, ServletException {
        // Given
        request.addHeader("tenantId", "test-tenant");
        request.setRequestURI("/oauth2/authorize");
        when(tenantConfigurationService.tenantExists("test-tenant")).thenReturn(true);
        
        // Simulate an exception in the filter chain
        doThrow(new RuntimeException("Test exception")).when(filterChain).doFilter(any(), any());

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            assertThrows(RuntimeException.class, () -> 
                tenantResolutionFilter.doFilter(request, response, filterChain));

            // Then - Context should still be cleared even when exception occurs
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("test-tenant"));
            tenantContextMock.verify(TenantContext::clear);
        }
    }

    

    @Test
    void complexPathExtractionShouldHandleNestedPaths() throws IOException, ServletException {
        // Given
        request.setRequestURI("/tenant/my-tenant/api/v1/oauth2/authorize");
        when(tenantConfigurationService.tenantExists("my-tenant")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should extract tenant from path
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("my-tenant"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void tenantResolutionFallbackChainShouldTestFallbackOrder() throws IOException, ServletException {
        // Given - Only parameter is available
        request.setRequestURI("/oauth2/authorize"); // No tenant path
        request.addParameter("tenantId", "fallback-tenant");
        when(tenantConfigurationService.tenantExists("fallback-tenant")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should fall back to parameter
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("fallback-tenant"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }


    @Test
    void tenantExtractionFromOauthTokenEndpoint() throws IOException, ServletException {
        // Given
        request.setRequestURI("/issuer1/oauth2/token");
        when(tenantConfigurationService.tenantExists("issuer1")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("issuer1"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void tenantExtractionFromOauthRevokeEndpoint() throws IOException, ServletException {
        // Given
        request.setRequestURI("/ecsp/oauth2/revoke");
        when(tenantConfigurationService.tenantExists("ecsp")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("ecsp"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void tenantExtractionFromOauthUserInfoEndpoint() throws IOException, ServletException {
        // Given
        request.setRequestURI("/demo/oauth2/userinfo");
        when(tenantConfigurationService.tenantExists("demo")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("demo"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void tenantExtractionFromOauthJwksEndpoint() throws IOException, ServletException {
        // Given
        request.setRequestURI("/issuer2/oauth2/jwks");
        when(tenantConfigurationService.tenantExists("issuer2")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("issuer2"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void tenantExtractionFromLoginEndpoint() throws IOException, ServletException {
        // Given
        request.setRequestURI("/ecsp/login/oauth2/code/google");
        when(tenantConfigurationService.tenantExists("ecsp")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("ecsp"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void tenantExtractionFromCustomRevokeAdminEndpoint() throws IOException, ServletException {
        // Given
        request.setRequestURI("/issuer1/revoke/revokeByAdmin");
        when(tenantConfigurationService.tenantExists("issuer1")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("issuer1"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void tenantExtractionFromOauthLogoutEndpoint() throws IOException, ServletException {
        // Given
        request.setRequestURI("/demo/oauth2/logout");
        when(tenantConfigurationService.tenantExists("demo")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("demo"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void excludedPathsShouldNotExtractTenant() throws IOException, ServletException {
        // Given - Test various excluded paths
        String[] excludedPaths = {
            "/api/oauth2/authorize",
            "/v1/oauth2/token", 
            "/public/oauth2/userinfo",
            "/health/oauth2/status",
            "/admin/oauth2/config",
            "/management/oauth2/info"
        };

        for (String excludedPath : excludedPaths) {
            request = new MockHttpServletRequest(); // Reset request
            request.setRequestURI(excludedPath);

            try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
                // When
                tenantResolutionFilter.doFilter(request, response, filterChain);

                // Then - Should return error response instead of proceeding
                assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus(), 
                    "Expected error response for excluded path: " + excludedPath);
                assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());
                
                String responseContent = response.getContentAsString();
                assertTrue(responseContent.contains("TENANT_NOT_FOUND_IN_REQUEST"),
                    "Expected TENANT_NOT_FOUND_IN_REQUEST for excluded path: " + excludedPath);

                tenantContextMock.verify(TenantContext::clear);
                verify(filterChain, never()).doFilter(request, response);
            }
        }
    }

    @Test
    void whenMultiTenantDisabledShouldSetTenantToDefault() throws IOException, ServletException {
        // Given
        setSpringProperties(false, "default-tenant");
        request.setRequestURI("/oauth2/authorize");
        when(tenantConfigurationService.tenantExists("default-tenant")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("default-tenant"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testTenantResolutionFromAuthorizationHeaderWithValidJwt() throws IOException, ServletException {
        // Arrange
        String expectedTenant = "sdp";
        // Create a valid JWT token with tenantId claim
        // JWT format: header.payload.signature (Base64 URL encoded)
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes());
        String payloadJson = "{\"sub\":\"admin\",\"tenantId\":\""
            + expectedTenant + "\",\"user_id\":\"12345\"}";
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.getBytes());
        String signature = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("fake-signature".getBytes());
        String jwtToken = header + "." + payload + "." + signature;

        String authHeader = "Bearer " + jwtToken;
        request.setRequestURI("/oauth2/authorize");
        request.addHeader("Authorization", authHeader);
        when(tenantConfigurationService.tenantExists(expectedTenant)).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(expectedTenant));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testTenantResolutionFromAuthorizationHeaderWithDifferentTenant() throws IOException, ServletException {
        // Arrange
        String expectedTenant = "ecsp";
        String payloadJson = "{\"sub\":\"testuser\",\"tenantId\":\""
            + expectedTenant + "\",\"accountName\":\"Engineering\"}";
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.getBytes());
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"HS256\"}".getBytes());
        String signature = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("signature".getBytes());
        String jwtToken = header + "." + payload + "." + signature;

        String authHeader = "Bearer " + jwtToken;
        request.setRequestURI("/oauth2/token");
        request.addHeader("Authorization", authHeader);
        when(tenantConfigurationService.tenantExists(expectedTenant)).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(expectedTenant));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testAuthorizationHeaderIgnoredWhenTenantIdHeaderPresent() throws IOException, ServletException {
        // Arrange - header should take precedence over Authorization
        String headerTenant = "ecsp";
        String authTenant = "sdp";

        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(("{\"tenantId\":\"" + authTenant + "\"}").getBytes());
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"HS256\"}".getBytes());
        String signature = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("sig".getBytes());
        String jwtToken = header + "." + payload + "." + signature;

        request.setRequestURI("/oauth2/authorize");
        request.addHeader("tenantId", headerTenant);
        request.addHeader("Authorization", "Bearer " + jwtToken);
        when(tenantConfigurationService.tenantExists(headerTenant)).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should use tenantId header, not Authorization
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(headerTenant));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testAuthorizationHeaderIgnoredWhenPathContainsTenant() throws IOException, ServletException {
        // Arrange - path should take precedence over Authorization
        String pathTenant = "ecsp";
        String authTenant = "sdp";

        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(("{\"tenantId\":\"" + authTenant + "\"}").getBytes());
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"HS256\"}".getBytes());
        String signature = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("sig".getBytes());
        String jwtToken = header + "." + payload + "." + signature;
        String requestUri = "/tenant/" + pathTenant + "/oauth2/authorize";

        request.setRequestURI(requestUri);
        request.addHeader("Authorization", "Bearer " + jwtToken);
        when(tenantConfigurationService.tenantExists(pathTenant)).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should use path tenant, not Authorization
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(pathTenant));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testInvalidJwtFormatIgnored() throws IOException, ServletException {
        // Arrange - invalid JWT (only 2 parts instead of 3)
        String invalidJwt = "header.payload"; // Missing signature
        String authHeader = "Bearer " + invalidJwt;

        request.setRequestURI("/oauth2/authorize");
        request.addHeader("Authorization", authHeader);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should fail to resolve tenant
            assertTenantNotFoundErrorResponse();
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void testNonBearerTokenIgnored() throws IOException, ServletException {
        // Arrange - Authorization header without Bearer prefix
        String authHeader = "Basic dXNlcjpwYXNzd29yZA=="; // Basic auth

        request.setRequestURI("/oauth2/authorize");
        request.addHeader("Authorization", authHeader);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should fail to resolve tenant
            assertTenantNotFoundErrorResponse();
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void testJwtWithoutTenantIdClaimIgnored() throws IOException, ServletException {
        // Arrange - JWT without tenantId claim
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"sub\":\"user\",\"role\":\"admin\"}".getBytes()); // No tenantId
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"HS256\"}".getBytes());
        String signature = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("sig".getBytes());
        String jwtToken = header + "." + payload + "." + signature;

        request.setRequestURI("/oauth2/authorize");
        request.addHeader("Authorization", "Bearer " + jwtToken);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should fail to resolve tenant
            assertTenantNotFoundErrorResponse();
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void testMalformedBase64InJwtIgnored() throws IOException, ServletException {
        // Arrange - JWT with invalid Base64 encoding
        String invalidJwt = "header.invalid-base64-!!!.signature";
        String authHeader = "Bearer " + invalidJwt;

        request.setRequestURI("/oauth2/authorize");
        request.addHeader("Authorization", authHeader);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should fail to resolve tenant
            assertTenantNotFoundErrorResponse();
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void testEmptyAuthorizationHeaderIgnored() throws IOException, ServletException {
        // Arrange
        request.setRequestURI("/oauth2/authorize");
        request.addHeader("Authorization", "");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should fail to resolve tenant
            assertTenantNotFoundErrorResponse();
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void testBearerTokenWithOnlyPrefixIgnored() throws IOException, ServletException {
        // Arrange - "Bearer " with no token
        request.setRequestURI("/oauth2/authorize");
        request.addHeader("Authorization", "Bearer ");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should fail to resolve tenant
            assertTenantNotFoundErrorResponse();
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain, never()).doFilter(request, response);
        }
    }

    @Test
    void testAuthorizationHeaderWithValidJwtFromUserinfoEndpoint() throws IOException, ServletException {
        // Arrange
        String expectedTenant = "demo";
        String payloadJson = "{\"sub\":\"john.doe\",\"tenantId\":\""
            + expectedTenant + "\",\"email\":\"john@example.com\"}";
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.getBytes());
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"RS256\"}".getBytes());
        String signature = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("valid-signature".getBytes());
        String jwtToken = header + "." + payload + "." + signature;

        request.setRequestURI("/oauth2/userinfo");
        request.addHeader("Authorization", "Bearer " + jwtToken);
        when(tenantConfigurationService.tenantExists(expectedTenant)).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(expectedTenant));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testAuthorizationHeaderFallbackWhenOtherStrategiesFail() throws IOException, ServletException {
        // Arrange - Only Authorization header provides tenant
        String expectedTenant = "issuer1";
        String payloadJson = "{\"sub\":\"api-client\",\"tenantId\":\"" + expectedTenant + "\"}";
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.getBytes());
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"RS256\"}".getBytes());
        String signature = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("sig".getBytes());
        String jwtToken = header + "." + payload + "." + signature;

        request.setRequestURI("/oauth2/introspect"); // No tenant in path
        // No tenantId header
        // No tenant parameter
        request.addHeader("Authorization", "Bearer " + jwtToken);
        when(tenantConfigurationService.tenantExists(expectedTenant)).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should use Authorization header as fallback
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(expectedTenant));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    // ========================================
    // Well-Known Endpoint Tests
    // ========================================

    @Test
    void wellKnownServerRootEndpointShouldWorkWhenMultitenancyEnabled()
            throws IOException, ServletException {
        // Given
        setSpringProperties(true, "ecsp");
        request.setRequestURI("/.well-known/oauth-authorization-server");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Root well-known endpoint without tenant should fail when multitenancy enabled
            // because no tenant can be resolved from the path
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("ecsp"), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain, never()).doFilter(request, response);
            assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
            String responseContent = response.getContentAsString();
            assertTrue(responseContent.contains("TENANT_NOT_FOUND_IN_REQUEST"));
        }
    }

    @Test
    void wellKnownServerRootEndpointShouldWorkWhenMultitenancyDisabled()
            throws IOException, ServletException {
        // Given
        setSpringProperties(false, "ecsp");
        request.setRequestURI("/.well-known/oauth-authorization-server");
        when(tenantConfigurationService.tenantExists("ecsp")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should use default tenant when multitenancy is disabled
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("ecsp"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
            assertEquals(HttpStatus.OK.value(), response.getStatus());
        }
    }

    @Test
    void wellKnownServerWithValidTenantPostfixShouldWorkWhenMultitenancyEnabled()
            throws IOException, ServletException {
        // Given
        setSpringProperties(true, "ecsp");
        request.setRequestURI("/.well-known/oauth-authorization-server/ecsp");
        when(tenantConfigurationService.tenantExists("ecsp")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should extract and validate tenant from postfix
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("ecsp"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void wellKnownServerWithDefaultTenantPostfixShouldWorkWhenMultitenancyDisabled()
            throws IOException, ServletException {
        // Given
        setSpringProperties(false, "ecsp");
        request.setRequestURI("/.well-known/oauth-authorization-server/ecsp");
        when(tenantConfigurationService.tenantExists("ecsp")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should allow default tenant postfix even when multitenancy is disabled
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("ecsp"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void wellKnownServerWithNonDefaultTenantPostfixShouldFailWhenMultitenancyDisabled()
            throws IOException, ServletException {
        // Given
        setSpringProperties(false, "ecsp");
        request.setRequestURI("/.well-known/oauth-authorization-server/sdp");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should reject non-default tenant when multitenancy is disabled
            // Validation throws exception, so tenant is never set
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("sdp"), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain, never()).doFilter(request, response);
            assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
            assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());
            String responseContent = response.getContentAsString();
            assertTrue(responseContent.contains("TENANT_RESOLUTION_FAILED"));
        }
    }

    @Test
    void wellKnownServerWithInvalidTenantPostfixShouldFailWhenMultitenancyEnabled()
            throws IOException, ServletException {
        // Given
        setSpringProperties(true, "ecsp");
        request.setRequestURI("/.well-known/oauth-authorization-server/invalid-tenant");
        when(tenantConfigurationService.tenantExists("invalid-tenant")).thenReturn(false);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should reject invalid tenant
            // Validation throws exception, so tenant is never set
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("invalid-tenant"), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain, never()).doFilter(request, response);
            // TenantResolutionException.invalidTenant returns BAD_REQUEST by default
            assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
            assertEquals(MediaType.APPLICATION_JSON_VALUE, response.getContentType());
            String responseContent = response.getContentAsString();
            assertTrue(responseContent.contains("TENANT_RESOLUTION_FAILED"));
        }
    }

    @Test
    void wellKnownOpenIdConfigurationWithValidTenantPostfixShouldWork() throws IOException, ServletException {
        // Given
        setSpringProperties(true, "ecsp");
        request.setRequestURI("/.well-known/openid-configuration/demo");
        when(tenantConfigurationService.tenantExists("demo")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("demo"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void wellKnownServerWithMultipleTenantsShouldWorkWhenMultitenancyEnabled()
            throws IOException, ServletException {
        // Given
        setSpringProperties(true, "ecsp");
        String[] tenants = {"ecsp", "sdp", "demo"};

        for (String tenant : tenants) {
            request = new MockHttpServletRequest();
            response = new MockHttpServletResponse();
            request.setRequestURI("/.well-known/oauth-authorization-server/" + tenant);
            when(tenantConfigurationService.tenantExists(tenant)).thenReturn(true);

            try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
                tenantResolutionFilter.doFilter(request, response, filterChain);
                tenantContextMock.verify(() -> TenantContext.setCurrentTenant(tenant));
                tenantContextMock.verify(TenantContext::clear);
            }
        }
    }

    @Test
    void tenantPrefixPatternShouldWorkWithWellKnownInPath() throws IOException, ServletException {
        // Given - Test pattern like /demo/.well-known/...
        setSpringProperties(true, "ecsp");
        request.setRequestURI("/demo/.well-known/oauth-authorization-server");
        when(tenantConfigurationService.tenantExists("demo")).thenReturn(true);

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should extract tenant from prefix pattern
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("demo"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }
}

