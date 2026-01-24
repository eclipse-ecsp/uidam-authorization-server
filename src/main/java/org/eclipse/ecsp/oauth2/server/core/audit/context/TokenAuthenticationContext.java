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
import org.eclipse.ecsp.audit.context.AuthenticationContext;

import java.util.HashMap;
import java.util.Map;

/**
 * Token Authentication Context - Contains OAuth2 token generation details.
 * Used for audit logging of token-related events (TOKEN_REFRESHED, ACCESS_TOKEN_GENERATED).
 * 
 * <p>Fields:</p>
 * <ul>
 *   <li>grantType - OAuth2 grant type (authorization_code, refresh_token, client_credentials)</li>
 *   <li>authType - Authentication method (password, idp:google, client_credentials)</li>
 *   <li>clientId - OAuth2 client identifier</li>
 *   <li>scopes - Requested/granted scopes</li>
 * </ul>
 *
 */
@Data
@Builder
public class TokenAuthenticationContext implements AuthenticationContext {
    
    private String grantType;
    private String authType;
    private String clientId;
    private String scopes;
    
    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        if (grantType != null) {
            map.put("grant_type", grantType);
        }
        if (authType != null) {
            map.put("auth_type", authType);
        }
        if (clientId != null) {
            map.put("client_id", clientId);
        }
        if (scopes != null) {
            map.put("scopes", scopes);
        }
        return map;
    }
}
