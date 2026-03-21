/*
 * Copyright (c) 2024 - 2025 Harman International
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.oauth2.server.core.audit.context;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Data;
import org.eclipse.ecsp.audit.context.RequestContext;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * HTTP Request Context Implementation.
 * 
 * <p>Captures HTTP request details for audit logging.</p>
 * 
 * <p><strong>Fields:</strong></p>
 * <ul>
 *   <li>sourceIpAddress - Client IP address</li>
 *   <li>userAgent - Browser/client identifier</li>
 *   <li>sessionId - HTTP session ID</li>
 *   <li>correlationId - Request correlation ID for distributed tracing</li>
 * </ul>
 *
 */
@Data
@Builder
public class HttpRequestContext implements RequestContext {
    
    /**
     * Source IP address (IPv4 or IPv6).
     * This will be stored in both source_ip_address field and in request_context JSON.
     */
    private String sourceIpAddress;
    
    /**
     * User agent string from HTTP header.
     */
    private String userAgent;
    
    /**
     * HTTP session identifier.
     */
    private String sessionId;
    
    /**
     * Correlation ID for distributed tracing.
     * This will be stored in both correlation_id field and in request_context JSON.
     */
    private String correlationId;
    
    /**
     * HTTP method (GET, POST, etc.).
     */
    private String method;
    
    /**
     * Request URI.
     */
    private String requestUri;
    
    /**
     * Factory method to create HttpRequestContext from HttpServletRequest.
     *
     * @param request the HTTP servlet request
     * @return HttpRequestContext instance
     */
    public static HttpRequestContext from(HttpServletRequest request) {
        if (request == null) {
            return HttpRequestContext.builder()
                .correlationId(UUID.randomUUID().toString())
                .build();
        }
        
        return HttpRequestContext.builder()
            .sourceIpAddress(getClientIpAddress(request))
            .userAgent(request.getHeader("User-Agent"))
            .sessionId(request.getSession(false) != null ? request.getSession(false).getId() : null)
            .correlationId(getOrGenerateCorrelationId(request))
            .method(request.getMethod())
            .requestUri(request.getRequestURI())
            .build();
    }
    
    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        
        // These fields are used to populate source_ip_address and correlation_id in audit_log table
        map.put("sourceIpAddress", sourceIpAddress);
        map.put("correlationId", correlationId);
        
        // Context details for JSONB request_context field
        if (userAgent != null) {
            map.put("userAgent", userAgent);
        }
        if (sessionId != null) {
            map.put("sessionId", sessionId);
        }
        if (method != null) {
            map.put("method", method);
        }
        if (requestUri != null) {
            map.put("requestUri", requestUri);
        }
        
        return map;
    }
    
    /**
     * Extract client IP address from HTTP request, handling X-Forwarded-For header.
     */
    private static String getClientIpAddress(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            // X-Forwarded-For can contain multiple IPs, take the first one (original client)
            return forwardedFor.split(",")[0].trim();
        }
        
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isEmpty()) {
            return realIp;
        }
        
        return request.getRemoteAddr();
    }
    
    /**
     * Get correlation ID from request header or generate a new one.
     */
    private static String getOrGenerateCorrelationId(HttpServletRequest request) {
        String correlationId = request.getHeader("X-Correlation-ID");
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = request.getHeader("X-Request-ID");
        }
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = UUID.randomUUID().toString();
        }
        return correlationId;
    }
}
