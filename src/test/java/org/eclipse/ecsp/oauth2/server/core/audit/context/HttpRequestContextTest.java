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

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

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
}
