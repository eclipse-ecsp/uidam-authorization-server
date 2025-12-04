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

package org.eclipse.ecsp.audit.logger;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.ecsp.audit.context.ActorContext;
import org.eclipse.ecsp.audit.context.AuthenticationContext;
import org.eclipse.ecsp.audit.context.RequestContext;
import org.eclipse.ecsp.audit.context.TargetContext;
import org.eclipse.ecsp.audit.entity.AuditEvent;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.repository.AuditRepository;
import org.eclipse.ecsp.audit.util.PiiMasker;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Default Audit Logger Implementation.
 * 
 * <p>Key features:</p>
 * <ul>
 *   <li>Uses REQUIRES_NEW transaction to ensure audit log is saved even if main transaction fails</li>
 *   <li>Automatically masks PII in context fields before saving</li>
 *   <li>Never throws exceptions - logs errors instead to avoid breaking main application flow</li>
 * </ul>
 *
 * @version 2.0.0
 * @since 1.2.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DefaultAuditLogger implements AuditLogger {
    
    private final AuditRepository auditRepository;
    
    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(String eventType,
                    String component,
                    AuditEventResult result,
                    String message,
                    ActorContext actorContext,
                    TargetContext targetContext,
                    RequestContext requestContext,
                    AuthenticationContext authContext) {
        try {
            AuditEvent event = AuditEvent.builder()
                .eventType(eventType)
                .component(component)
                .result(result)
                .message(message)
                .actorId(extractActorId(actorContext))
                .actorType(extractActorType(actorContext))
                .actorContext(maskAndSerialize(actorContext))
                .targetId(extractTargetId(targetContext))
                .targetType(extractTargetType(targetContext))
                .targetContext(maskAndSerialize(targetContext))
                .sourceIpAddress(extractSourceIp(requestContext))
                .correlationId(extractCorrelationId(requestContext))
                .requestContext(maskAndSerialize(requestContext))
                .authenticationContext(maskAndSerialize(authContext))
                .build();
            
            auditRepository.save(event);
            
            log.debug("Audit event saved: eventType={}, component={}, actorId={}", 
                eventType, component, event.getActorId());
                
        } catch (Exception e) {
            log.error("Failed to save audit log: eventType={}, component={}, error={}", 
                eventType, component, e.getMessage(), e);
        }
    }
    
    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(String eventType,
                    String component,
                    AuditEventResult result,
                    ActorContext actorContext,
                    RequestContext requestContext) {
        log(eventType, component, result, null, actorContext, null, requestContext, null);
    }
    
    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(String eventType,
                    String component,
                    AuditEventResult result,
                    String message,
                    ActorContext actorContext,
                    RequestContext requestContext) {
        try {
            AuditEvent event = AuditEvent.builder()
                .eventType(eventType)
                .component(component)
                .result(result)
                .message(message)
                .actorId(extractActorId(actorContext))
                .actorType(extractActorType(actorContext))
                .actorContext(maskAndSerialize(actorContext))
                .sourceIpAddress(extractSourceIp(requestContext))
                .correlationId(extractCorrelationId(requestContext))
                .requestContext(maskAndSerialize(requestContext))
                .build();
            
            auditRepository.save(event);
            
            log.debug("Audit event with message saved: eventType={}, actorId={}", 
                eventType, event.getActorId());
                
        } catch (Exception e) {
            log.error("Failed to save audit log with message: eventType={}, error={}", 
                eventType, e.getMessage(), e);
        }
    }
    
    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logFailure(String eventType,
                          String component,
                          String failureCode,
                          String failureReason,
                          ActorContext actorContext,
                          RequestContext requestContext) {
        try {
            AuditEvent event = AuditEvent.builder()
                .eventType(eventType)
                .component(component)
                .result(AuditEventResult.FAILURE)
                .failureCode(failureCode)
                .failureReason(failureReason)
                .actorId(extractActorId(actorContext))
                .actorType(extractActorType(actorContext))
                .actorContext(maskAndSerialize(actorContext))
                .sourceIpAddress(extractSourceIp(requestContext))
                .correlationId(extractCorrelationId(requestContext))
                .requestContext(maskAndSerialize(requestContext))
                .build();
            
            auditRepository.save(event);
            
            log.debug("Audit failure logged: eventType={}, failureCode={}, actorId={}", 
                eventType, failureCode, event.getActorId());
                
        } catch (Exception e) {
            log.error("Failed to save audit failure log: eventType={}, failureCode={}, error={}", 
                eventType, failureCode, e.getMessage(), e);
        }
    }
    
    // ========== Helper Methods ==========
    
    private String maskAndSerialize(Object context) {
        if (context == null) {
            return null;
        }
        
        if (context instanceof ActorContext) {
            return PiiMasker.maskAndSerialize(((ActorContext) context).toMap());
        } else if (context instanceof TargetContext) {
            return PiiMasker.maskAndSerialize(((TargetContext) context).toMap());
        } else if (context instanceof RequestContext) {
            return PiiMasker.maskAndSerialize(((RequestContext) context).toMap());
        } else if (context instanceof AuthenticationContext) {
            return PiiMasker.maskAndSerialize(((AuthenticationContext) context).toMap());
        }
        
        return null;
    }
    
    private String extractActorId(ActorContext context) {
        if (context == null || context.toMap() == null) {
            return null;
        }
        Object actorId = context.toMap().get("actorId");
        return actorId != null ? String.valueOf(actorId) : null;
    }
    
    private String extractActorType(ActorContext context) {
        if (context == null || context.toMap() == null) {
            return null;
        }
        Object actorType = context.toMap().get("actorType");
        return actorType != null ? String.valueOf(actorType) : null;
    }
    
    private String extractTargetId(TargetContext context) {
        if (context == null || context.toMap() == null) {
            return null;
        }
        Object targetId = context.toMap().get("targetId");
        return targetId != null ? String.valueOf(targetId) : null;
    }
    
    private String extractTargetType(TargetContext context) {
        if (context == null || context.toMap() == null) {
            return null;
        }
        Object targetType = context.toMap().get("targetType");
        return targetType != null ? String.valueOf(targetType) : null;
    }
    
    private String extractSourceIp(RequestContext context) {
        if (context == null || context.toMap() == null) {
            return null;
        }
        Object sourceIp = context.toMap().get("sourceIpAddress");
        return sourceIp != null ? String.valueOf(sourceIp) : null;
    }
    
    private String extractCorrelationId(RequestContext context) {
        if (context == null || context.toMap() == null) {
            return null;
        }
        Object correlationId = context.toMap().get("correlationId");
        return correlationId != null ? String.valueOf(correlationId) : null;
    }
}
