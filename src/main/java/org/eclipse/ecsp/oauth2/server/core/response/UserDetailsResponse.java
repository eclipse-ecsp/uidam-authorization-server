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

package org.eclipse.ecsp.oauth2.server.core.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * The UserDetailsResponse class represents the response containing user details.
 */
@Getter
@Setter
@ToString
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDetailsResponse {

    private String id;
    private String userName;
    @ToString.Exclude
    private String password;
    @ToString.Exclude
    private String passwordEncoder;
    @ToString.Exclude
    private String salt;
    private String tenantId;
    private String accountId;
    private String status;
    private String email;
    private String lastSuccessfulLoginTime;
    private Integer failureLoginAttempts;

    private Map<String, Object> captcha = new HashMap<>();

    private Set<String> roles;
    private Set<String> scopes;
    /**
     * Per-user MFA override for CONDITIONAL policy, sourced from the
     * {@code mfaRequired} user attribute in user-management.
     * <ul>
     *   <li>{@code true}  – MFA is always required for this user in CONDITIONAL mode.</li>
     *   <li>{@code false} – MFA is explicitly exempted for this user in CONDITIONAL mode.</li>
     *   <li>{@code null}  – No per-user override; normal step-up evaluation applies.</li>
     * </ul>
     */
    private Boolean mfaRequired;
    private Map<String, Object> additionalAttributes = new HashMap<>();
    private boolean isVerificationEmailSent;
}
