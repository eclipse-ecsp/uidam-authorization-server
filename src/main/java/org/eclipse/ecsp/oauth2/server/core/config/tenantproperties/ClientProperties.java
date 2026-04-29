/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;


import lombok.Getter;
import lombok.Setter;

/**
 * The ClientProperties class represents the properties related to a tenant's OAuth client.
 */
@Getter
@Setter
public class ClientProperties {
    private Integer accessTokenTtl;
    private Integer idTokenTtl;
    private Integer refreshTokenTtl;
    private Integer authCodeTtl;
    private Boolean oauthScopeCustomization; //if its true then customize scopes to be present
    private String secretEncryptionKey;
    private String secretEncryptionSalt;
    private Boolean reuseRefreshToken;
    /**
     * If true, for authorization_code grant type scopeless users (users with no explicitly assigned scopes),
     * all user scopes from the user details will be included in the 'scope' and 'scopes' claims.
     */
    private Boolean authCodeScopelessUserScopes;
}