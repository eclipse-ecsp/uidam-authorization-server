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

import lombok.Builder;
import lombok.Data;
import org.eclipse.ecsp.audit.context.ActorContext;

import java.util.HashMap;
import java.util.Map;

/**
 * User Actor Context Implementation.
 * 
 * <p>Captures details about the user (actor) performing an action in UIDAM.</p>
 * 
 * <p><strong>PII Fields (auto-masked):</strong></p>
 * <ul>
 *   <li>username - User's login identifier</li>
 *   <li>accountName - Account display name</li>
 * </ul>
 *
 */
@Data
@Builder
public class UserActorContext implements ActorContext {
    
    /**
     * User ID from UIDAM users table.
     * This will be stored in both actor_id field (as VARCHAR) and in actor_context JSON.
     */
    private String userId;
    
    /**
     * Username for the user (e.g., email or login ID).
     * PII - will be masked in actor_context JSON.
     */
    private String username;
    
    /**
     * Account ID associated with the user.
     */
    private String accountId;
    
    /**
     * Account name for readability.
     * PII - will be masked in actor_context JSON.
     */
    private String accountName;
    
    /**
     * Number of failed login attempts (for failure events).
     */
    private Integer failedAttempts;
    
    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        
        // These fields are used to populate actor_id and actor_type in audit_log table
        map.put("actorId", userId);
        map.put("actorType", "USER");
        
        // Context details for JSONB actor_context field
        if (username != null) {
            map.put("username", username);  // PII - will be masked
        }
        if (accountId != null) {
            map.put("accountId", accountId);
        }
        if (accountName != null) {
            map.put("accountName", accountName);  // PII - will be masked
        }
        if (failedAttempts != null) {
            map.put("failedAttempts", failedAttempts);
        }
        
        return map;
    }
}
