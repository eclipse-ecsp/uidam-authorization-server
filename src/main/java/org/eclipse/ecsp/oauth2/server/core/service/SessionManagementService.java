/********************************************************************************
 * Copyright (c) 2023-24 Harman International
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

package org.eclipse.ecsp.oauth2.server.core.service;

import org.eclipse.ecsp.oauth2.server.core.response.dto.ActiveSessionsResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.InvalidateSessionsResponseDto;

import java.util.List;

/**
 * Service interface for managing active sessions.
 */
public interface SessionManagementService {
    
    /**
     * Retrieves active sessions for a user.
     *
     * @param username the username
     * @param currentTokenString the current JWT token string (nullable, for self-service operations)
     * @param tenantId the tenant ID
     * @return the active sessions response
     */
    ActiveSessionsResponseDto getActiveSessionsForUser(String username, String currentTokenString, String tenantId);
    
    /**
     * Invalidates specified sessions for a user.
     *
     * @param username the username
     * @param tokenIds the list of token IDs to invalidate
     * @param tenantId the tenant ID
     * @return the invalidate sessions response
     */
    InvalidateSessionsResponseDto invalidateSessionsForUser(String username, List<String> tokenIds, String tenantId);
}
