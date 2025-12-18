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

import org.eclipse.ecsp.audit.entity.AuditEvent;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for AuditEventDto.
 */
@SuppressWarnings("checkstyle:MagicNumber")
class AuditEventDtoTest {

    @Test
    void builder_ShouldCreateDtoWithAllFields() {
        // Given
        Instant now = Instant.now();
        
        // When
        AuditEventDto dto = AuditEventDto.builder()
            .id(BigInteger.valueOf(123))
            .eventType("LOGIN")
            .component("AUTH_SERVICE")
            .result(AuditEventResult.SUCCESS)
            .timestamp(now)
            .tenantId("tenant-123")
            .actorId("user-456")
            .actorType("USER")
            .targetId("resource-789")
            .targetType("ACCOUNT")
            .sourceIpAddress("192.168.1.1")
            .correlationId("corr-123")
            .actorContext("{\"username\":\"john\"}")
            .targetContext("{\"accountId\":\"acc-1\"}")
            .requestContext("{\"method\":\"POST\"}")
            .authenticationContext("{\"authType\":\"PASSWORD\"}")
            .failureCode("AUTH_001")
            .failureReason("Invalid credentials")
            .beforeValue("{\"status\":\"active\"}")
            .afterValue("{\"status\":\"locked\"}")
            .additionalData("{\"attempts\":3}")
            .message("Login attempt")
            .build();
        
        // Then
        assertThat(dto).isNotNull();
        assertThat(dto.getId()).isEqualTo(BigInteger.valueOf(123));
        assertThat(dto.getEventType()).isEqualTo("LOGIN");
        assertThat(dto.getComponent()).isEqualTo("AUTH_SERVICE");
        assertThat(dto.getResult()).isEqualTo(AuditEventResult.SUCCESS);
        assertThat(dto.getTimestamp()).isEqualTo(now);
        assertThat(dto.getTenantId()).isEqualTo("tenant-123");
        assertThat(dto.getActorId()).isEqualTo("user-456");
        assertThat(dto.getActorType()).isEqualTo("USER");
        assertThat(dto.getTargetId()).isEqualTo("resource-789");
        assertThat(dto.getTargetType()).isEqualTo("ACCOUNT");
        assertThat(dto.getSourceIpAddress()).isEqualTo("192.168.1.1");
        assertThat(dto.getCorrelationId()).isEqualTo("corr-123");
        assertThat(dto.getActorContext()).isEqualTo("{\"username\":\"john\"}");
        assertThat(dto.getTargetContext()).isEqualTo("{\"accountId\":\"acc-1\"}");
        assertThat(dto.getRequestContext()).isEqualTo("{\"method\":\"POST\"}");
        assertThat(dto.getAuthenticationContext()).isEqualTo("{\"authType\":\"PASSWORD\"}");
        assertThat(dto.getFailureCode()).isEqualTo("AUTH_001");
        assertThat(dto.getFailureReason()).isEqualTo("Invalid credentials");
        assertThat(dto.getBeforeValue()).isEqualTo("{\"status\":\"active\"}");
        assertThat(dto.getAfterValue()).isEqualTo("{\"status\":\"locked\"}");
        assertThat(dto.getAdditionalData()).isEqualTo("{\"attempts\":3}");
        assertThat(dto.getMessage()).isEqualTo("Login attempt");
    }

    @Test
    void fromEntity_WithNullEntity_ShouldReturnNull() {
        // When
        AuditEventDto dto = AuditEventDto.fromEntity(null);
        
        // Then
        assertThat(dto).isNull();
    }

    @Test
    void fromEntity_WithCompleteEntity_ShouldMapAllFields() {
        // Given
        Instant now = Instant.now();
        AuditEvent entity = AuditEvent.builder()
            .id(BigInteger.valueOf(999))
            .eventType("LOGOUT")
            .component("AUTH_SERVER")
            .result(AuditEventResult.FAILURE)
            .timestamp(now)
            .tenantId("ecsp")
            .actorId("user-123")
            .actorType("ADMIN")
            .targetId("session-456")
            .targetType("SESSION")
            .sourceIpAddress("10.0.0.1")
            .correlationId("xyz-789")
            .actorContext("{\"role\":\"admin\"}")
            .targetContext("{\"sessionId\":\"s1\"}")
            .requestContext("{\"uri\":\"/logout\"}")
            .authenticationContext("{\"method\":\"token\"}")
            .failureCode("ERR_002")
            .failureReason("Session expired")
            .beforeValue("{\"active\":true}")
            .afterValue("{\"active\":false}")
            .additionalData("{\"reason\":\"timeout\"}")
            .message("User logged out")
            .build();
        
        // When
        AuditEventDto dto = AuditEventDto.fromEntity(entity);
        
        // Then
        assertThat(dto).isNotNull();
        assertThat(dto.getId()).isEqualTo(entity.getId());
        assertThat(dto.getEventType()).isEqualTo(entity.getEventType());
        assertThat(dto.getComponent()).isEqualTo(entity.getComponent());
        assertThat(dto.getResult()).isEqualTo(entity.getResult());
        assertThat(dto.getTimestamp()).isEqualTo(entity.getTimestamp());
        assertThat(dto.getTenantId()).isEqualTo(entity.getTenantId());
        assertThat(dto.getActorId()).isEqualTo(entity.getActorId());
        assertThat(dto.getActorType()).isEqualTo(entity.getActorType());
        assertThat(dto.getTargetId()).isEqualTo(entity.getTargetId());
        assertThat(dto.getTargetType()).isEqualTo(entity.getTargetType());
        assertThat(dto.getSourceIpAddress()).isEqualTo(entity.getSourceIpAddress());
        assertThat(dto.getCorrelationId()).isEqualTo(entity.getCorrelationId());
        assertThat(dto.getActorContext()).isEqualTo(entity.getActorContext());
        assertThat(dto.getTargetContext()).isEqualTo(entity.getTargetContext());
        assertThat(dto.getRequestContext()).isEqualTo(entity.getRequestContext());
        assertThat(dto.getAuthenticationContext()).isEqualTo(entity.getAuthenticationContext());
        assertThat(dto.getFailureCode()).isEqualTo(entity.getFailureCode());
        assertThat(dto.getFailureReason()).isEqualTo(entity.getFailureReason());
        assertThat(dto.getBeforeValue()).isEqualTo(entity.getBeforeValue());
        assertThat(dto.getAfterValue()).isEqualTo(entity.getAfterValue());
        assertThat(dto.getAdditionalData()).isEqualTo(entity.getAdditionalData());
        assertThat(dto.getMessage()).isEqualTo(entity.getMessage());
    }

    @Test
    void fromEntity_WithMinimalEntity_ShouldMapRequiredFieldsOnly() {
        // Given
        Instant now = Instant.now();
        AuditEvent entity = AuditEvent.builder()
            .id(BigInteger.valueOf(1))
            .eventType("TEST_EVENT")
            .component("TEST_COMPONENT")
            .result(AuditEventResult.SUCCESS)
            .timestamp(now)
            .build();
        
        // When
        AuditEventDto dto = AuditEventDto.fromEntity(entity);
        
        // Then
        assertThat(dto).isNotNull();
        assertThat(dto.getId()).isEqualTo(BigInteger.valueOf(1));
        assertThat(dto.getEventType()).isEqualTo("TEST_EVENT");
        assertThat(dto.getComponent()).isEqualTo("TEST_COMPONENT");
        assertThat(dto.getResult()).isEqualTo(AuditEventResult.SUCCESS);
        assertThat(dto.getTimestamp()).isEqualTo(now);
        assertThat(dto.getTenantId()).isNull();
        assertThat(dto.getActorId()).isNull();
        assertThat(dto.getMessage()).isNull();
    }

    @Test
    void equals_WithSameValues_ShouldBeEqual() {
        // Given
        Instant now = Instant.now();
        AuditEventDto dto1 = AuditEventDto.builder()
            .id(BigInteger.valueOf(1))
            .eventType("LOGIN")
            .component("AUTH")
            .result(AuditEventResult.SUCCESS)
            .timestamp(now)
            .build();
        
        AuditEventDto dto2 = AuditEventDto.builder()
            .id(BigInteger.valueOf(1))
            .eventType("LOGIN")
            .component("AUTH")
            .result(AuditEventResult.SUCCESS)
            .timestamp(now)
            .build();
        
        // Then
        assertThat(dto1).isEqualTo(dto2);
        assertThat(dto1.hashCode()).isEqualTo(dto2.hashCode());
    }

    @Test
    void toString_ShouldContainAllFields() {
        // Given
        AuditEventDto dto = AuditEventDto.builder()
            .id(BigInteger.valueOf(123))
            .eventType("LOGIN")
            .component("AUTH_SERVICE")
            .result(AuditEventResult.SUCCESS)
            .actorId("user-456")
            .build();
        
        // When
        String toString = dto.toString();
        
        // Then
        assertThat(toString).contains("id=123");
        assertThat(toString).contains("eventType=LOGIN");
        assertThat(toString).contains("component=AUTH_SERVICE");
        assertThat(toString).contains("result=SUCCESS");
        assertThat(toString).contains("actorId=user-456");
    }
}
