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

package org.eclipse.ecsp.audit.logger;

import org.eclipse.ecsp.audit.context.ActorContext;
import org.eclipse.ecsp.audit.context.AuthenticationContext;
import org.eclipse.ecsp.audit.context.RequestContext;
import org.eclipse.ecsp.audit.context.TargetContext;
import org.eclipse.ecsp.audit.entity.AuditEvent;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.repository.AuditRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for DefaultAuditLogger.
 */
@ExtendWith(MockitoExtension.class)
class DefaultAuditLoggerTest {

    @Mock
    private AuditRepository auditRepository;

    @InjectMocks
    private DefaultAuditLogger auditLogger;

    private ActorContext actorContext;
    private TargetContext targetContext;
    private RequestContext requestContext;
    private AuthenticationContext authContext;

    @BeforeEach
    void setUp() {
        actorContext = createActorContext("user123", "USER");
        targetContext = createTargetContext("resource456", "RESOURCE");
        requestContext = createRequestContext("192.168.1.1", "corr-123");
        authContext = createAuthContext("password", 0);
    }

    @Test
    void logWithAllParametersShouldSaveAuditEvent() {
        // Given
        when(auditRepository.save(any(AuditEvent.class))).thenAnswer(i -> i.getArgument(0));
        ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);

        // When
        auditLogger.log(
            "AUTH_SUCCESS",
            "test-component",
            AuditEventResult.SUCCESS,
            "User authenticated successfully",
            actorContext,
            targetContext,
            requestContext,
            authContext
        );

        // Then
        verify(auditRepository, times(1)).save(eventCaptor.capture());
        AuditEvent savedEvent = eventCaptor.getValue();
        
        assertThat(savedEvent.getEventType()).isEqualTo("AUTH_SUCCESS");
        assertThat(savedEvent.getComponent()).isEqualTo("test-component");
        assertThat(savedEvent.getResult()).isEqualTo(AuditEventResult.SUCCESS);
        assertThat(savedEvent.getMessage()).isEqualTo("User authenticated successfully");
        assertThat(savedEvent.getActorId()).isEqualTo("user123");
        assertThat(savedEvent.getActorType()).isEqualTo("USER");
        assertThat(savedEvent.getTargetId()).isEqualTo("resource456");
        assertThat(savedEvent.getTargetType()).isEqualTo("RESOURCE");
        assertThat(savedEvent.getSourceIpAddress()).isEqualTo("192.168.1.1");
        assertThat(savedEvent.getCorrelationId()).isEqualTo("corr-123");
        assertThat(savedEvent.getActorContext()).isNotNull();
        assertThat(savedEvent.getTargetContext()).isNotNull();
        assertThat(savedEvent.getRequestContext()).isNotNull();
        assertThat(savedEvent.getAuthenticationContext()).isNotNull();
    }

    @Test
    void logWithMinimalParametersShouldSaveAuditEvent() {
        // Given
        when(auditRepository.save(any(AuditEvent.class))).thenAnswer(i -> i.getArgument(0));
        ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);

        // When
        auditLogger.log(
            "AUTH_FAILURE",
            "test-component",
            AuditEventResult.FAILURE,
            actorContext,
            requestContext
        );

        // Then
        verify(auditRepository, times(1)).save(eventCaptor.capture());
        AuditEvent savedEvent = eventCaptor.getValue();
        
        assertThat(savedEvent.getEventType()).isEqualTo("AUTH_FAILURE");
        assertThat(savedEvent.getComponent()).isEqualTo("test-component");
        assertThat(savedEvent.getResult()).isEqualTo(AuditEventResult.FAILURE);
        assertThat(savedEvent.getMessage()).isNull();
        assertThat(savedEvent.getActorId()).isEqualTo("user123");
        assertThat(savedEvent.getTargetContext()).isNull();
        assertThat(savedEvent.getAuthenticationContext()).isNull();
    }

    @Test
    void logWithMessageShouldSaveAuditEvent() {
        // Given
        when(auditRepository.save(any(AuditEvent.class))).thenAnswer(i -> i.getArgument(0));
        ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);

        // When
        auditLogger.log(
            "LOGOUT",
            "test-component",
            AuditEventResult.SUCCESS,
            "User logged out successfully",
            actorContext,
            requestContext
        );

        // Then
        verify(auditRepository, times(1)).save(eventCaptor.capture());
        AuditEvent savedEvent = eventCaptor.getValue();
        
        assertThat(savedEvent.getEventType()).isEqualTo("LOGOUT");
        assertThat(savedEvent.getMessage()).isEqualTo("User logged out successfully");
        assertThat(savedEvent.getActorId()).isEqualTo("user123");
    }

    @Test
    void logFailureShouldSaveAuditEventWithFailureDetails() {
        // Given
        when(auditRepository.save(any(AuditEvent.class))).thenAnswer(i -> i.getArgument(0));
        ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);

        // When
        auditLogger.logFailure(
            "AUTH_FAILURE",
            "test-component",
            "ERR_INVALID_CREDENTIALS",
            "Invalid username or password",
            actorContext,
            requestContext
        );

        // Then
        verify(auditRepository, times(1)).save(eventCaptor.capture());
        AuditEvent savedEvent = eventCaptor.getValue();
        
        assertThat(savedEvent.getEventType()).isEqualTo("AUTH_FAILURE");
        assertThat(savedEvent.getResult()).isEqualTo(AuditEventResult.FAILURE);
        assertThat(savedEvent.getFailureCode()).isEqualTo("ERR_INVALID_CREDENTIALS");
        assertThat(savedEvent.getFailureReason()).isEqualTo("Invalid username or password");
    }

    @Test
    void logWithNullContextsShouldNotThrowException() {
        // Given
        when(auditRepository.save(any(AuditEvent.class))).thenAnswer(i -> i.getArgument(0));

        // When - no exception should be thrown
        auditLogger.log(
            "TEST_EVENT",
            "test-component",
            AuditEventResult.SUCCESS,
            "Test message",
            null,
            null,
            null,
            null
        );

        // Then
        verify(auditRepository, times(1)).save(any(AuditEvent.class));
    }

    @Test
    void logShouldNotThrowExceptionWhenRepositoryFails() {
        // Given
        when(auditRepository.save(any(AuditEvent.class)))
            .thenThrow(new RuntimeException("Database error"));

        // When - no exception should propagate
        auditLogger.log(
            "TEST_EVENT",
            "test-component",
            AuditEventResult.SUCCESS,
            actorContext,
            requestContext
        );

        // Then - verify repository was called but exception was caught
        verify(auditRepository, times(1)).save(any(AuditEvent.class));
    }

    @Test
    void logShouldExtractActorIdFromActorContext() {
        // Given
        ActorContext contextWithId = createActorContext("actor789", "SERVICE");
        when(auditRepository.save(any(AuditEvent.class))).thenAnswer(i -> i.getArgument(0));
        ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);

        // When
        auditLogger.log(
            "TEST_EVENT",
            "test-component",
            AuditEventResult.SUCCESS,
            contextWithId,
            requestContext
        );

        // Then
        verify(auditRepository).save(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getActorId()).isEqualTo("actor789");
        assertThat(eventCaptor.getValue().getActorType()).isEqualTo("SERVICE");
    }

    @Test
    void logShouldExtractTargetIdFromTargetContext() {
        // Given
        TargetContext contextWithId = createTargetContext("target999", "API");
        when(auditRepository.save(any(AuditEvent.class))).thenAnswer(i -> i.getArgument(0));
        ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);

        // When
        auditLogger.log(
            "TEST_EVENT",
            "test-component",
            AuditEventResult.SUCCESS,
            "Test",
            actorContext,
            contextWithId,
            requestContext,
            null
        );

        // Then
        verify(auditRepository).save(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getTargetId()).isEqualTo("target999");
        assertThat(eventCaptor.getValue().getTargetType()).isEqualTo("API");
    }

    @Test
    void logShouldExtractSourceIpFromRequestContext() {
        // Given
        RequestContext contextWithIp = createRequestContext("10.0.0.1", "test-corr");
        when(auditRepository.save(any(AuditEvent.class))).thenAnswer(i -> i.getArgument(0));
        ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);

        // When
        auditLogger.log(
            "TEST_EVENT",
            "test-component",
            AuditEventResult.SUCCESS,
            actorContext,
            contextWithIp
        );

        // Then
        verify(auditRepository).save(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getSourceIpAddress()).isEqualTo("10.0.0.1");
        assertThat(eventCaptor.getValue().getCorrelationId()).isEqualTo("test-corr");
    }

    // Helper methods to create test contexts
    private ActorContext createActorContext(String actorId, String actorType) {
        return new ActorContext() {
            @Override
            public Map<String, Object> toMap() {
                Map<String, Object> map = new HashMap<>();
                map.put("actorId", actorId);
                map.put("actorType", actorType);
                return map;
            }
        };
    }

    private TargetContext createTargetContext(String targetId, String targetType) {
        return new TargetContext() {
            @Override
            public Map<String, Object> toMap() {
                Map<String, Object> map = new HashMap<>();
                map.put("targetId", targetId);
                map.put("targetType", targetType);
                return map;
            }
        };
    }

    private RequestContext createRequestContext(String sourceIp, String correlationId) {
        return new RequestContext() {
            @Override
            public Map<String, Object> toMap() {
                Map<String, Object> map = new HashMap<>();
                map.put("sourceIpAddress", sourceIp);
                map.put("correlationId", correlationId);
                return map;
            }
        };
    }

    private AuthenticationContext createAuthContext(String authType, int failedAttempts) {
        return new AuthenticationContext() {
            @Override
            public Map<String, Object> toMap() {
                Map<String, Object> map = new HashMap<>();
                map.put("authType", authType);
                map.put("failedAttempts", failedAttempts);
                return map;
            }
        };
    }
}
