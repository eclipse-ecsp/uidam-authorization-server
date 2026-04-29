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
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import java.util.Map;
import java.util.Set;

/**
 * The ExternalIdpRegisteredClient class represents the properties related to an
 * external Identity Provider (IDP) registered client for a tenant.
 */
@Getter
@Setter
public class ExternalIdpRegisteredClient {

    private boolean enabled;
    private String clientName;
    private String registrationId;
    private String clientId;
    private String clientSecret;
    private String clientAuthenticationMethod;
    private String scope;
    private String authorizationUri;
    private String tokenUri;
    private String userInfoUri;
    private String userNameAttributeName;
    private String jwkSetUri;
    private String tokenInfoSource;
    private String createUserMode;
    private Set<String> defaultUserRoles;

    private String claimMappings; // Holds comma-separated values
    private Map<String, String> mappings; // Populated after parsing
    private Condition conditions; // Condition configuration for IDP

    /**
     * Claims conditions.
     */
    @Getter
    @Setter
    public static class Condition {
        private String claimKey;
        private String expectedValue;
        private String operator; // e.g., "equals" or "in"

    }

    /**
     * This method is used to get the client authentication method. It returns the
     * corresponding ClientAuthenticationMethod enum value based on the
     * clientAuthenticationMethod string value. If the string value is not
     * recognized, it throws an IllegalArgumentException.
     *
     * @return the corresponding ClientAuthenticationMethod enum value
     * @throws IllegalArgumentException if the clientAuthenticationMethod string
     *                                  value is not recognized
     */
    // Can be optimized
    public ClientAuthenticationMethod getClientAuthMethod() {
        return switch (clientAuthenticationMethod) {
            case "client_secret_basic" -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
            case "client_secret_post" -> ClientAuthenticationMethod.CLIENT_SECRET_POST;
            case "client_secret_jwt" -> ClientAuthenticationMethod.CLIENT_SECRET_JWT;
            case "private_key_jwt" -> ClientAuthenticationMethod.PRIVATE_KEY_JWT;
            case "none" -> ClientAuthenticationMethod.NONE;
            default -> throw new IllegalArgumentException("Invalid Client Authentication Method");
        };
    }

}