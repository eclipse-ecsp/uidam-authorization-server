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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;


/**
 * Test class for TenantResolutionFilter.
 * Tests all tenant resolution strategies and edge cases.
 */
@ExtendWith(MockitoExtension.class)
class TenantResolutionFilterTest {

    private TenantResolutionFilter tenantResolutionFilter;

    @Mock
    private FilterChain filterChain;

    @Mock
    private FilterConfig filterConfig;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        tenantResolutionFilter = new TenantResolutionFilter();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @AfterEach
    void tearDown() {
        // Ensure tenant context is cleared after each test
        TenantContext.clear();
    }

    @Test
    void testInit() {
        // Test that init method completes without exception
        assertDoesNotThrow(() -> tenantResolutionFilter.init(filterConfig));
    }

    @Test
    void testDestroy() {
        // Test that destroy method completes without exception
        assertDoesNotThrow(() -> tenantResolutionFilter.destroy());
    }

    @Test
    void testTenantResolutionFromHeader() throws IOException, ServletException {
        // Given
        request.addHeader("tenantId", "test-tenant");
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("test-tenant"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    //@Test
    void testTenantResolutionFromSubdomain() throws IOException, ServletException {
        // Given
        request.setServerName("ecsp.example.com");
        request.setRequestURI("/oauth2/authorize");

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
    void testTenantResolutionFromPath() throws IOException, ServletException {
        // Given
        request.setRequestURI("/tenant/ecsp/oauth2/authorize");

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
    void testTenantResolutionFromParameter() throws IOException, ServletException {
        // Given
        request.addParameter("tenant", "param-tenant");
        request.setRequestURI("/oauth2/authorize");

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
    void testTenantResolutionPriority() throws IOException, ServletException {
        // Given - Set all possible tenant sources
        request.addHeader("tenantId", "header-tenant");
        request.setServerName("subdomain.example.com");
        request.setRequestURI("/tenant/path-tenant/oauth2/authorize");
        request.addParameter("tenant", "param-tenant");

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
    void testNoTenantResolved() throws IOException, ServletException {
        // Given - No tenant information in request
        request.setRequestURI("/oauth2/authorize");
        request.setServerName("example.com"); // No subdomain

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - No tenant should be set
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(() -> TenantContext.clear());
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testEmptyTenantHeader() throws IOException, ServletException {
        // Given
        request.addHeader("tenantId", "");
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Empty header should be ignored
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testNullTenantHeader() throws IOException, ServletException {
        // Given - No header is added (simulating null header)
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Null header should be ignored
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testWhitespaceOnlyTenantHeader() throws IOException, ServletException {
        // Given
        request.addHeader("tenantId", "   ");
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Whitespace-only header should be ignored
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testSubdomainExtractionWithInsufficientParts() throws IOException, ServletException {
        // Given
        request.setServerName("example.com"); // Only 2 parts
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - No tenant should be set
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testSubdomainExtractionWithEmptyServerName() throws IOException, ServletException {
        // Given
        request.setServerName("");
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - No tenant should be set
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testSubdomainExtractionWithNullServerName() throws IOException, ServletException {
        // Given
        request.setServerName(null);
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - No tenant should be set
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testPathExtractionWithInvalidPath() throws IOException, ServletException {
        // Given
        request.setRequestURI("/tenant/"); // Missing tenant ID
        request.setServerName("example.com");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - No tenant should be set
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testPathExtractionWithShortPath() throws IOException, ServletException {
        // Given
        request.setRequestURI("/tenant"); // Too short
        request.setServerName("example.com");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - No tenant should be set
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testPathExtractionWithNonTenantPath() throws IOException, ServletException {
        // Given
        request.setRequestURI("/api/v1/oauth2/authorize");
        request.setServerName("example.com");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - No tenant should be set
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testPathExtractionWithEmptyPath() throws IOException, ServletException {
        // Given
        request.setRequestURI("");
        request.setServerName("example.com");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - No tenant should be set
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testPathExtractionWithNullPath() throws IOException, ServletException {
        // Given
        request.setRequestURI(null);
        request.setServerName("example.com");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - No tenant should be set
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testParameterExtractionWithEmptyParameter() throws IOException, ServletException {
        // Given
        request.addParameter("tenant", "");
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Empty parameter should be ignored
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testParameterExtractionWithNullParameter() throws IOException, ServletException {
        // Given
        request.addParameter("tenant", (String) null);
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Null parameter should be ignored
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant(any()), never());
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testTenantContextAlwaysCleared() throws IOException, ServletException {
        // Given
        request.addHeader("tenantId", "test-tenant");
        request.setRequestURI("/oauth2/authorize");
        
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

    //@Test
    void testComplexSubdomainExtraction() throws IOException, ServletException {
        // Given
        request.setServerName("tenant1.dev.example.com");
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then - Should extract first part as tenant
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("tenant1"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testComplexPathExtraction() throws IOException, ServletException {
        // Given
        request.setRequestURI("/tenant/my-tenant/api/v1/oauth2/authorize");

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
    void testTenantResolutionFallbackChain() throws IOException, ServletException {
        // Given - Only parameter is available
        request.setServerName("example.com"); // No subdomain
        request.setRequestURI("/oauth2/authorize"); // No tenant path
        request.addParameter("tenant", "fallback-tenant");

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
    void testTenantResolutionWithSpecialCharacters() throws IOException, ServletException {
        // Given
        request.addHeader("tenantId", "tenant-with-dashes_and_underscores");
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("tenant-with-dashes_and_underscores"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }

    @Test
    void testTenantResolutionWithNumericTenant() throws IOException, ServletException {
        // Given
        request.addHeader("tenantId", "123456");
        request.setRequestURI("/oauth2/authorize");

        try (MockedStatic<TenantContext> tenantContextMock = mockStatic(TenantContext.class)) {
            // When
            tenantResolutionFilter.doFilter(request, response, filterChain);

            // Then
            tenantContextMock.verify(() -> TenantContext.setCurrentTenant("123456"));
            tenantContextMock.verify(TenantContext::clear);
            verify(filterChain).doFilter(request, response);
        }
    }
}
