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

package org.eclipse.ecsp.oauth2.server.core.audit.enums;

/**
 * Audit Event Types - Authorization Server events.
 * 
 * <p><strong>Design Note:</strong> This enum is part of the CALLER's code (not the common audit framework).
 * Each service defines its own event types. The audit framework accepts String event types via getType().</p>
 * 
 * <p>This enum contains ONLY authentication and authorization events
 * relevant to the UIDAM Authorization Server. User management events
 * are maintained separately in the User Management Service.</p>
 * 
 * <p>Each enum constant contains:</p>
 * <ul>
 *   <li>Event Type - unique identifier stored in database</li>
 *   <li>Description - human-readable explanation of the event</li>
 * </ul>
 * 
 * <p><strong>Usage:</strong></p>
 * <pre>{@code
 * // Caller defines event type enum and calls getType()
 * auditLogger.log(
 *     AuditEventType.AUTH_SUCCESS_PASSWORD.getType(),  // String passed to framework
 *     "uidam-authorization-server",
 *     AuditEventResult.SUCCESS,
 *     actorContext,
 *     requestContext
 * );
 * 
 * // Description can be logged separately if needed
 * log.info("Audit: {}", AuditEventType.AUTH_SUCCESS_PASSWORD.getDescription());
 * }</pre>
 *
 * @version 3.0.0
 * @since 1.2.0
 */
public enum AuditEventType {
    
    // ========== Authentication Events ==========
    
    AUTH_SUCCESS_PASSWORD("AUTH_SUCCESS_PASSWORD", "User authenticated successfully via password"),
    AUTH_SUCCESS_IDP("AUTH_SUCCESS_IDP", "User authenticated successfully via external identity provider"),
    AUTH_FAILURE_WRONG_PASSWORD("AUTH_FAILURE_WRONG_PASSWORD", "User authentication failed - wrong password"),
    AUTH_FAILURE_USER_NOT_FOUND("AUTH_FAILURE_USER_NOT_FOUND", "User authentication failed - user not found"),
    AUTH_FAILURE_USER_BLOCKED("AUTH_FAILURE_USER_BLOCKED", "User authentication failed - user is blocked"),
    AUTH_FAILURE_ACCOUNT_NOT_FOUND("AUTH_FAILURE_ACCOUNT_NOT_FOUND", "User authentication failed - account not found"),
    AUTH_FAILURE_ACCOUNT_LOCKED("AUTH_FAILURE_ACCOUNT_LOCKED", "User authentication failed - account is locked"),
    AUTH_FAILURE_CAPTCHA("AUTH_FAILURE_CAPTCHA", "User authentication failed - CAPTCHA validation failed"),
    LOGOUT("LOGOUT", "User logged out successfully"),
    TOKEN_REFRESHED("TOKEN_REFRESHED", "Access token refreshed using refresh token"),
    ACCESS_TOKEN_GENERATED("ACCESS_TOKEN_GENERATED", "Access token generated successfully"),
    
    // ========== Authorization Events ==========
    
    AUTHZ_FAILURE_REVOKED_TOKEN("AUTHZ_FAILURE_REVOKED_TOKEN", "Authorization failed - token has been revoked");
    
    private final String type;
    private final String description;
    
    /**
     * Constructor.
     *
     * @param type the event type identifier
     * @param description the human-readable description
     */
    AuditEventType(String type, String description) {
        this.type = type;
        this.description = description;
    }
    
    /**
     * Get the event type identifier.
     *
     * @return the event type string
     */
    public String getType() {
        return type;
    }
    
    /**
     * Get the human-readable description.
     *
     * @return the event description
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Check if this event is authentication-related.
     *
     * @return true if authentication event
     */
    public boolean isAuthentication() {
        return type.startsWith("AUTH_") || this == LOGOUT || this == TOKEN_REFRESHED 
            || this == ACCESS_TOKEN_GENERATED;
    }
    
    /**
     * Check if this event is authorization-related.
     *
     * @return true if authorization event
     */
    public boolean isAuthorization() {
        return type.startsWith("AUTHZ_") || type.startsWith("RBAC_") || type.startsWith("SCOPE_");
    }
    
    /**
     * Find enum by type string.
     *
     * @param type the event type to find
     * @return the matching enum or null if not found
     */
    public static AuditEventType fromType(String type) {
        if (type == null) {
            return null;
        }
        for (AuditEventType eventType : values()) {
            if (eventType.type.equals(type)) {
                return eventType;
            }
        }
        return null;
    }
    
    @Override
    public String toString() {
        return type;
    }
}
