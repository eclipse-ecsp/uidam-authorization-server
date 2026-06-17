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

package org.eclipse.ecsp.oauth2.server.core.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.math.BigInteger;
import java.sql.Timestamp;

/**
 * The AuthorizationSecurityContext class represents the security context of an OAuth 2.0 Authorization.
 * This class holds state related to the authentication object of the security context.
 */
@Getter
@Setter
@Entity
@ToString
@Table(name = "`authorization_security_context`")
public class AuthorizationSecurityContext {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, updatable = false, columnDefinition = "NUMERIC(38) DEFAULT get_uuid()")
    private BigInteger id;
    @Column(name = "PRINCIPAL", nullable = false)
    private String principal;
    @Column(name = "ACCOUNT_NAME")
    private String accountName;
    @Column(name = "AUTHORITIES")
    private String authorities;
    @Column(name = "AUTHORIZED_CLIENT_REGISTRATION_ID")
    private String authorizedClientRegistrationId;
    @Column(name = "AUTHENTICATED", nullable = false)
    private Boolean authenticated;
    @Column(name = "REMOTE_IP_ADDRESS")
    private String remoteIpAddress;
    @Column(name = "SESSION_ID", nullable = false)
    private String sessionId;
    @Column(name = "CREATED_DATE", nullable = false)
    private Timestamp createdDate;
    @Column(name = "UPDATED_DATE", nullable = false)
    private Timestamp updatedDate;

    // ── MFA pending state (replaces HttpSession attributes) ─────────────────
    /** Username whose password-auth passed but MFA challenge not yet completed. {@code null} = no pending MFA. */
    @Column(name = "MFA_PENDING_USERNAME")
    private String mfaPendingUsername;
    /** Comma-separated GrantedAuthority strings for the pending-MFA user. */
    @Column(name = "MFA_PENDING_AUTHORITIES")
    private String mfaPendingAuthorities;
    /** Resolved tenant ID stored alongside the pending MFA token. */
    @Column(name = "MFA_TENANT")
    private String mfaTenant;
    /**
     * Single-use flag consumed by {@code MfaChallengeFilter} on the first
     * {@code /oauth2/authorize} request that follows a successful MFA verification
     * to prevent the filter from re-intercepting and looping.
     */
    @Column(name = "MFA_VERIFIED_ONCE")
    private Boolean mfaVerifiedOnce = Boolean.FALSE;

}