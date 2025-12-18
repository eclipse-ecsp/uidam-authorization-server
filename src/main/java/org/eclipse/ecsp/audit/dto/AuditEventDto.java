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

package org.eclipse.ecsp.audit.dto;

import lombok.Builder;
import lombok.Data;
import org.eclipse.ecsp.audit.entity.AuditEvent;
import org.eclipse.ecsp.audit.enums.AuditEventResult;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Audit Event DTO - Transfer object for audit events.
 * 
 * <p>Use builder pattern for easy event creation.</p>
 *
 */
@Data
@Builder
public class AuditEventDto {
    
    private BigInteger id;
    
    // Core fields
    private String eventType;
    private String component;
    private AuditEventResult result;
    private Instant timestamp;
    
    // Multi-tenancy (optional - NULL for UIDAM)
    private String tenantId;
    
    // Generic Identity
    private String actorId;
    private String actorType;
    private String targetId;
    private String targetType;
    
    // Security Context
    private String sourceIpAddress;
    private String correlationId;
    
    // Context (summary only - not full JSONB)
    private String actorContext;
    private String targetContext;
    private String requestContext;
    private String authenticationContext;
    
    // Failure Information
    private String failureCode;
    private String failureReason;
    
    // Change Tracking
    private String beforeValue;
    private String afterValue;
    
    // Additional Data
    private String additionalData;
    
    // Message
    private String message;
    
    /**
     * Convert from entity to DTO.
     *
     * @param entity audit event entity
     * @return DTO
     */
    public static AuditEventDto fromEntity(AuditEvent entity) {
        if (entity == null) {
            return null;
        }
        
        return AuditEventDto.builder()
            .id(entity.getId())
            .eventType(entity.getEventType())
            .component(entity.getComponent())
            .result(entity.getResult())
            .timestamp(entity.getTimestamp())
            .tenantId(entity.getTenantId())
            .actorId(entity.getActorId())
            .actorType(entity.getActorType())
            .targetId(entity.getTargetId())
            .targetType(entity.getTargetType())
            .sourceIpAddress(entity.getSourceIpAddress())
            .correlationId(entity.getCorrelationId())
            .actorContext(entity.getActorContext())
            .targetContext(entity.getTargetContext())
            .requestContext(entity.getRequestContext())
            .authenticationContext(entity.getAuthenticationContext())
            .failureCode(entity.getFailureCode())
            .failureReason(entity.getFailureReason())
            .beforeValue(entity.getBeforeValue())
            .afterValue(entity.getAfterValue())
            .additionalData(entity.getAdditionalData())
            .message(entity.getMessage())
            .build();
    }
}
