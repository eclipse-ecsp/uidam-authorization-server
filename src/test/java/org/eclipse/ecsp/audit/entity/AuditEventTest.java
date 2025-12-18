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

import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for AuditEvent entity.
 */
@SuppressWarnings("checkstyle:MagicNumber")
class AuditEventTest {

    @Test
    void onCreate_ShouldSetTimestampAndDefaultResult() {
        // Given
        AuditEvent event = AuditEvent.builder()
            .eventType("TEST_EVENT")
            .component("TEST_COMPONENT")
            .build();
        
        // When
        event.onCreate();
        
        // Then
        assertThat(event.getTimestamp()).isNotNull();
        assertThat(event.getResult()).isEqualTo(AuditEventResult.SUCCESS);
    }

    @Test
    void onCreate_ShouldNotOverrideExistingTimestamp() {
        // Given
        Instant existingTimestamp = Instant.now().minusSeconds(60);
        AuditEvent event = AuditEvent.builder()
            .eventType("TEST_EVENT")
            .component("TEST_COMPONENT")
            .timestamp(existingTimestamp)
            .build();
        
        // When
        event.onCreate();
        
        // Then
        assertThat(event.getTimestamp()).isEqualTo(existingTimestamp);
    }

    @Test
    void onCreate_ShouldNotOverrideExistingResult() {
        // Given
        AuditEvent event = AuditEvent.builder()
            .eventType("TEST_EVENT")
            .component("TEST_COMPONENT")
            .result(AuditEventResult.FAILURE)
            .build();
        
        // When
        event.onCreate();
        
        // Then
        assertThat(event.getResult()).isEqualTo(AuditEventResult.FAILURE);
    }

    @Test
    void builder_ShouldCreateEntityWithAllFields() {
        // Given
        Instant now = Instant.now();
        
        // When
        AuditEvent event = AuditEvent.builder()
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
        assertThat(event).isNotNull();
        assertThat(event.getId()).isEqualTo(BigInteger.valueOf(123));
        assertThat(event.getEventType()).isEqualTo("LOGIN");
        assertThat(event.getComponent()).isEqualTo("AUTH_SERVICE");
        assertThat(event.getResult()).isEqualTo(AuditEventResult.SUCCESS);
        assertThat(event.getTimestamp()).isEqualTo(now);
        assertThat(event.getTenantId()).isEqualTo("tenant-123");
        assertThat(event.getActorId()).isEqualTo("user-456");
        assertThat(event.getActorType()).isEqualTo("USER");
        assertThat(event.getTargetId()).isEqualTo("resource-789");
        assertThat(event.getTargetType()).isEqualTo("ACCOUNT");
        assertThat(event.getSourceIpAddress()).isEqualTo("192.168.1.1");
        assertThat(event.getCorrelationId()).isEqualTo("corr-123");
        assertThat(event.getActorContext()).isEqualTo("{\"username\":\"john\"}");
        assertThat(event.getTargetContext()).isEqualTo("{\"accountId\":\"acc-1\"}");
        assertThat(event.getRequestContext()).isEqualTo("{\"method\":\"POST\"}");
        assertThat(event.getAuthenticationContext()).isEqualTo("{\"authType\":\"PASSWORD\"}");
        assertThat(event.getFailureCode()).isEqualTo("AUTH_001");
        assertThat(event.getFailureReason()).isEqualTo("Invalid credentials");
        assertThat(event.getBeforeValue()).isEqualTo("{\"status\":\"active\"}");
        assertThat(event.getAfterValue()).isEqualTo("{\"status\":\"locked\"}");
        assertThat(event.getAdditionalData()).isEqualTo("{\"attempts\":3}");
        assertThat(event.getMessage()).isEqualTo("Login attempt");
    }

    @Test
    void equals_WithSameValues_ShouldBeEqual() {
        // Given
        Instant now = Instant.now();
        AuditEvent event1 = AuditEvent.builder()
            .id(BigInteger.valueOf(1))
            .eventType("LOGIN")
            .component("AUTH")
            .result(AuditEventResult.SUCCESS)
            .timestamp(now)
            .build();
        
        AuditEvent event2 = AuditEvent.builder()
            .id(BigInteger.valueOf(1))
            .eventType("LOGIN")
            .component("AUTH")
            .result(AuditEventResult.SUCCESS)
            .timestamp(now)
            .build();
        
        // Then
        assertThat(event1).isEqualTo(event2);
        assertThat(event1.hashCode()).isEqualTo(event2.hashCode());
    }

    @Test
    void toString_ShouldContainKeyFields() {
        // Given
        AuditEvent event = AuditEvent.builder()
            .id(BigInteger.valueOf(123))
            .eventType("LOGIN")
            .component("AUTH_SERVICE")
            .result(AuditEventResult.SUCCESS)
            .actorId("user-456")
            .build();
        
        // When
        String toString = event.toString();
        
        // Then
        assertThat(toString).contains("id=123");
        assertThat(toString).contains("eventType=LOGIN");
        assertThat(toString).contains("component=AUTH_SERVICE");
        assertThat(toString).contains("result=SUCCESS");
        assertThat(toString).contains("actorId=user-456");
    }
}
