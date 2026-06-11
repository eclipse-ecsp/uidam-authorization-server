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

package org.eclipse.ecsp.audit.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Audit Event Entity - Generic audit framework for comprehensive security and compliance tracking.
 * 
 * <p>Features:</p>
 * <ul>
 *   <li>Generic VARCHAR identifiers for flexibility across components</li>
 *   <li>JSONB context fields with automatic PII masking</li>
 *   <li>Optional tenant_id for multi-tenancy (NULL for UIDAM)</li>
 *   <li>NUMERIC(38) primary key using database UUID function</li>
 * </ul>
 *
 */
@Entity
@Table(name = "audit_log")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditEvent {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID", nullable = false, updatable = false, columnDefinition = "NUMERIC(38) DEFAULT get_uuid()")
    private BigInteger id;
    
    @Column(name = "EVENT_TYPE", nullable = false, length = 256)
    private String eventType;
    
    @Column(name = "COMPONENT", nullable = false, length = 256)
    private String component;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "RESULT", nullable = false, length = 64)
    private AuditEventResult result;
    
    @Column(name = "TIMESTAMP", nullable = false)
    private Instant timestamp;
    
    @Column(name = "TENANT_ID", length = 256)
    private String tenantId;
    
    @Column(name = "ACTOR_ID", length = 256)
    private String actorId;
    
    @Column(name = "ACTOR_TYPE", length = 64)
    private String actorType;
    
    @Column(name = "TARGET_ID", length = 256)
    private String targetId;
    
    @Column(name = "TARGET_TYPE", length = 256)
    private String targetType;
    
    @Column(name = "SOURCE_IP_ADDRESS", length = 64)
    private String sourceIpAddress;
    
    @Column(name = "CORRELATION_ID", length = 256)
    private String correlationId;
    
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "ACTOR_CONTEXT", columnDefinition = "JSONB")
    private String actorContext;
    
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "TARGET_CONTEXT", columnDefinition = "JSONB")
    private String targetContext;
    
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "REQUEST_CONTEXT", columnDefinition = "JSONB")
    private String requestContext;
    
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "AUTHENTICATION_CONTEXT", columnDefinition = "JSONB")
    private String authenticationContext;
    
    @Column(name = "FAILURE_CODE", length = 64)
    private String failureCode;
    
    @Column(name = "FAILURE_REASON", length = 256)
    private String failureReason;
    
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "BEFORE_VALUE", columnDefinition = "JSONB")
    private String beforeValue;
    
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "AFTER_VALUE", columnDefinition = "JSONB")
    private String afterValue;
    
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "ADDITIONAL_DATA", columnDefinition = "JSONB")
    private String additionalData;
    
    @Column(name = "MESSAGE", columnDefinition = "TEXT")
    private String message;
    
    @PrePersist
    protected void onCreate() {
        if (timestamp == null) {
            timestamp = Instant.now();
        }
        if (result == null) {
            result = AuditEventResult.SUCCESS;
        }
    }
}
