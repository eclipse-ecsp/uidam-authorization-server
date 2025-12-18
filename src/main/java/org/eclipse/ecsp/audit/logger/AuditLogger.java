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

import org.eclipse.ecsp.audit.context.ActorContext;
import org.eclipse.ecsp.audit.context.AuthenticationContext;
import org.eclipse.ecsp.audit.context.RequestContext;
import org.eclipse.ecsp.audit.context.TargetContext;
import org.eclipse.ecsp.audit.enums.AuditEventResult;

/**
 * Audit Logger - SLF4J-style interface for logging audit events.
 * 
 * <p>Usage example:</p>
 * <pre>{@code
 * auditLogger.log(
 *     AuditEventType.AUTH_SUCCESS_PASSWORD,
 *     "UIDAM_AUTHORIZATION_SERVER",
 *     AuditEventResult.SUCCESS,
 *     actorContext,
 *     requestContext,
 *     authContext
 * );
 * }</pre>
 *
 * @version 2.0.0
 * @since 1.2.0
 */
public interface AuditLogger {
    
    /**
     * Log an audit event with full context.
     *
     * @param eventType event type constant (e.g., "AUTH_SUCCESS_PASSWORD")
     * @param component component name (e.g., "UIDAM_AUTHORIZATION_SERVER")
     * @param result event result
     * @param message additional descriptive message (optional, can be null)
     * @param actorContext actor information (PII will be masked)
     * @param targetContext target information (PII will be masked), can be null
     * @param requestContext request information (PII will be masked), can be null
     * @param authContext authentication information (PII will be masked), can be null
     */
    void log(String eventType,
             String component,
             AuditEventResult result,
             String message,
             ActorContext actorContext,
             TargetContext targetContext,
             RequestContext requestContext,
             AuthenticationContext authContext);
    
    /**
     * Log an audit event with minimal context (actor and request only).
     *
     * @param eventType event type constant (e.g., "AUTH_SUCCESS_PASSWORD")
     * @param component component name (e.g., "UIDAM_AUTHORIZATION_SERVER")
     * @param result event result
     * @param actorContext actor information (PII will be masked)
     * @param requestContext request information (PII will be masked), can be null
     */
    void log(String eventType,
             String component,
             AuditEventResult result,
             ActorContext actorContext,
             RequestContext requestContext);
    
    /**
     * Log an audit event with message.
     *
     * @param eventType event type constant (e.g., "AUTH_SUCCESS_PASSWORD")
     * @param component component name (e.g., "UIDAM_AUTHORIZATION_SERVER")
     * @param result event result
     * @param message additional message
     * @param actorContext actor information (PII will be masked)
     * @param requestContext request information (PII will be masked), can be null
     */
    void log(String eventType,
             String component,
             AuditEventResult result,
             String message,
             ActorContext actorContext,
             RequestContext requestContext);
    
    /**
     * Log an audit event with failure information.
     *
     * @param eventType event type constant (e.g., "AUTH_FAILURE_PASSWORD")
     * @param component component name (e.g., "UIDAM_AUTHORIZATION_SERVER")
     * @param failureCode machine-readable failure code
     * @param failureReason human-readable failure reason
     * @param actorContext actor information (PII will be masked)
     * @param requestContext request information (PII will be masked), can be null
     */
    void logFailure(String eventType,
                    String component,
                    String failureCode,
                    String failureReason,
                    ActorContext actorContext,
                    RequestContext requestContext);
}
