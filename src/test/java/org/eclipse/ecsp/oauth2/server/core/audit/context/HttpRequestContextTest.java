/********************************************************************************
 * Copyright (c) 2024-25 Harman International 
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

package org.eclipse.ecsp.oauth2.server.core.audit.context;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for HttpRequestContext.
 */
@SuppressWarnings("checkstyle:MagicNumber")
class HttpRequestContextTest {

    @Test
    void toMapShouldReturnAllFields() {
        // Given
        HttpRequestContext context = HttpRequestContext.builder()
            .sourceIpAddress("192.168.1.100")
            .userAgent("Mozilla/5.0")
            .method("POST")
            .requestUri("/api/auth/login")
            .correlationId("corr-12345")
            .sessionId("session-67890")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("sourceIpAddress", "192.168.1.100");
        assertThat(map).containsEntry("userAgent", "Mozilla/5.0");
        assertThat(map).containsEntry("method", "POST");
        assertThat(map).containsEntry("requestUri", "/api/auth/login");
        assertThat(map).containsEntry("correlationId", "corr-12345");
        assertThat(map).containsEntry("sessionId", "session-67890");
    }

    @Test
    void toMapWithNullValuesShouldNotIncludeNullFields() {
        // Given
        HttpRequestContext context = HttpRequestContext.builder()
            .sourceIpAddress("10.0.0.1")
            .requestUri("/api/test")
            .correlationId("corr-123")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("sourceIpAddress", "10.0.0.1");
        assertThat(map).containsEntry("requestUri", "/api/test");
        assertThat(map).containsEntry("correlationId", "corr-123");
        assertThat(map).doesNotContainKey("userAgent");
        assertThat(map).doesNotContainKey("sessionId");
    }

    @Test
    void toMapWithMinimalDataShouldWork() {
        // Given
        HttpRequestContext context = HttpRequestContext.builder()
            .sourceIpAddress("172.16.0.1")
            .correlationId("corr-min")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).hasSize(2);  // sourceIpAddress and correlationId always included
        assertThat(map.get("sourceIpAddress")).isEqualTo("172.16.0.1");
        assertThat(map.get("correlationId")).isEqualTo("corr-min");
    }

    @Test
    void builderShouldCreateValidInstance() {
        // When
        HttpRequestContext context = HttpRequestContext.builder()
            .sourceIpAddress("127.0.0.1")
            .userAgent("TestAgent/1.0")
            .method("GET")
            .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getSourceIpAddress()).isEqualTo("127.0.0.1");
        assertThat(context.getUserAgent()).isEqualTo("TestAgent/1.0");
        assertThat(context.getMethod()).isEqualTo("GET");
    }

    @Test
    void toMapWithGetRequestShouldIncludeMethodAndUri() {
        // Given
        HttpRequestContext context = HttpRequestContext.builder()
            .sourceIpAddress("192.168.0.1")
            .method("GET")
            .requestUri("/api/users/profile")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map.get("method")).isEqualTo("GET");
        assertThat(map.get("requestUri")).isEqualTo("/api/users/profile");
    }

    @Test
    void toMapWithCorrelationIdShouldIncludeIt() {
        // Given
        HttpRequestContext context = HttpRequestContext.builder()
            .sourceIpAddress("10.1.1.1")
            .correlationId("trace-abc-123")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("correlationId", "trace-abc-123");
    }

    @Test
    void toMapWithSessionIdShouldIncludeIt() {
        // Given
        HttpRequestContext context = HttpRequestContext.builder()
            .sourceIpAddress("192.168.2.50")
            .sessionId("JSESSIONID-xyz789")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("sessionId", "JSESSIONID-xyz789");
    }

    @Test
    void fromWithNullRequestShouldGenerateCorrelationId() {
        // When
        HttpRequestContext context = HttpRequestContext.from(null);

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getCorrelationId()).isNotNull();
        assertThat(context.getCorrelationId()).isNotEmpty();
        assertThat(context.getSourceIpAddress()).isNull();
        assertThat(context.getUserAgent()).isNull();
        assertThat(context.getSessionId()).isNull();
    }

    @Test
    void fromWithCompleteRequestShouldExtractAllFields() {
        // Given
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpSession session = mock(HttpSession.class);
        
        when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.195");
        when(request.getHeader("X-Correlation-ID")).thenReturn("test-correlation-id");
        when(request.getSession(false)).thenReturn(session);
        when(session.getId()).thenReturn("session-123");
        when(request.getMethod()).thenReturn("POST");
        when(request.getRequestURI()).thenReturn("/api/login");

        // When
        HttpRequestContext context = HttpRequestContext.from(request);

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getSourceIpAddress()).isEqualTo("203.0.113.195");
        assertThat(context.getUserAgent()).isEqualTo("Mozilla/5.0");
        assertThat(context.getSessionId()).isEqualTo("session-123");
        assertThat(context.getCorrelationId()).isEqualTo("test-correlation-id");
        assertThat(context.getMethod()).isEqualTo("POST");
        assertThat(context.getRequestUri()).isEqualTo("/api/login");
    }

    @Test
    void fromWithRealIpHeader() {
        // Given
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        when(request.getHeader("X-Real-IP")).thenReturn("198.51.100.42");
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
        when(request.getSession(false)).thenReturn(null);

        // When
        HttpRequestContext context = HttpRequestContext.from(request);

        // Then
        assertThat(context.getSourceIpAddress()).isEqualTo("198.51.100.42");
        assertThat(context.getSessionId()).isNull();
    }

    @Test
    void fromWithRemoteAddrOnlyShouldUseRemoteAddr() {
        // Given
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        when(request.getRemoteAddr()).thenReturn("192.0.2.1");
        when(request.getSession(false)).thenReturn(null);

        // When
        HttpRequestContext context = HttpRequestContext.from(request);

        // Then
        assertThat(context.getSourceIpAddress()).isEqualTo("192.0.2.1");
    }

    @Test
    void fromWithRequestIdHeader() {
        // Given
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        when(request.getHeader("X-Request-ID")).thenReturn("request-id-456");
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
        when(request.getSession(false)).thenReturn(null);

        // When
        HttpRequestContext context = HttpRequestContext.from(request);

        // Then
        assertThat(context.getCorrelationId()).isEqualTo("request-id-456");
    }

    @Test
    void fromWithMultipleIpsInForwardedFor() {
        // Given
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.195, 192.168.1.1, 10.0.0.1");
        when(request.getSession(false)).thenReturn(null);

        // When
        HttpRequestContext context = HttpRequestContext.from(request);

        // Then
        assertThat(context.getSourceIpAddress()).isEqualTo("203.0.113.195");
    }

    @Test
    void fromWithoutCorrelationHeadersShouldGenerateUuid() {
        // Given
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
        when(request.getSession(false)).thenReturn(null);

        // When
        HttpRequestContext context = HttpRequestContext.from(request);

        // Then
        assertThat(context.getCorrelationId()).isNotNull();
        assertThat(context.getCorrelationId()).isNotEmpty();
        assertThat(context.getCorrelationId()).matches(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    }
}
