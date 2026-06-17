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

package org.eclipse.ecsp.oauth2.server.core.authentication.tokens;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * The CustomUserPwdAuthenticationToken class extends the UsernamePasswordAuthenticationToken class from Spring
 * Security.
 * This class is used to represent a user's authentication token with an additional account name property.
 */
public class CustomUserPwdAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private String accountName;

    /**
     * The account ID of the user, sourced from the user-management service record
     * (same origin as the user's granted scopes).  This is distinct from
     * {@link #accountName} which is the login-form input provided by the user.
     */
    private String accountId;

    /**
     * Per-user MFA override for CONDITIONAL policy, sourced from the
     * {@code mfaRequired} user attribute in user-management.
     * {@code true} = always enforce; {@code false} = always skip; {@code null} = use normal step-up rules.
     */
    private Boolean mfaRequired;

    /**
     * Constructor for CustomUserPwdAuthenticationToken.
     * It initializes principal, credentials and accountName.
     *
     * @param principal The principal (user) making the request.
     * @param credentials The credentials of the user.
     * @param accountName The account name of the user.
     */
    public CustomUserPwdAuthenticationToken(Object principal, Object credentials,
                                            String accountName) {
        super(principal, credentials);
        this.accountName = accountName;
    }

    /**
     * Constructor for CustomUserPwdAuthenticationToken.
     * It initializes principal, credentials, accountName and authorities.
     *
     * @param principal The principal (user) making the request.
     * @param credentials The credentials of the user.
     * @param accountName The account name of the user.
     * @param authorities The authorities granted to the user.
     */
    public CustomUserPwdAuthenticationToken(Object principal, Object credentials,
                                            String accountName,
                                            Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
        this.accountName = accountName;
    }

    /**
     * Constructor for CustomUserPwdAuthenticationToken with accountId.
     * It initializes principal, credentials, accountName, accountId and authorities.
     *
     * @param principal The principal (user) making the request.
     * @param credentials The credentials of the user.
     * @param accountName The account name from the login request.
     * @param accountId The account ID sourced from the user record in user-management.
     * @param authorities The authorities granted to the user.
     */
    public CustomUserPwdAuthenticationToken(Object principal, Object credentials,
                                            String accountName, String accountId,
                                            Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
        this.accountName = accountName;
        this.accountId = accountId;
    }

    /**
     * Constructor for CustomUserPwdAuthenticationToken with accountId and mfaRequired.
     *
     * @param principal The principal (user) making the request.
     * @param credentials The credentials of the user.
     * @param accountName The account name from the login request.
     * @param accountId The account ID sourced from the user record in user-management.
     * @param mfaRequired Per-user MFA override from the user attribute; {@code null} means use normal rules.
     * @param authorities The authorities granted to the user.
     */
    public CustomUserPwdAuthenticationToken(Object principal, Object credentials,
                                            String accountName, String accountId, Boolean mfaRequired,
                                            Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
        this.accountName = accountName;
        this.accountId = accountId;
        this.mfaRequired = mfaRequired;
    }

    /**
     * This method creates an unauthenticated CustomUserPwdAuthenticationToken.
     *
     * @param principal The principal (user) making the request.
     * @param credentials The credentials of the user.
     * @param accountName The account name of the user.
     * @return An unauthenticated CustomUserPwdAuthenticationToken.
     */
    public static CustomUserPwdAuthenticationToken unauthenticated(Object principal, Object credentials,
                                                                   String accountName) {
        return new CustomUserPwdAuthenticationToken(principal, credentials, accountName);
    }

    /**
     * This method creates an authenticated CustomUserPwdAuthenticationToken.
     *
     * @param principal The principal (user) making the request.
     * @param credentials The credentials of the user.
     * @param accountName The account name of the user.
     * @param authorities The authorities granted to the user.
     * @return An authenticated CustomUserPwdAuthenticationToken.
     */
    public static CustomUserPwdAuthenticationToken authenticated(Object principal, Object credentials,
                                                                 String accountName,
                                                                 Collection<? extends GrantedAuthority> authorities) {
        return new CustomUserPwdAuthenticationToken(principal, credentials, accountName, authorities);
    }

    /**
     * Creates an authenticated token carrying both the login-form account name and the
     * account ID sourced from the user-management service record.
     *
     * @param principal The principal (user) making the request.
     * @param credentials The credentials of the user.
     * @param accountName The account name from the login request.
     * @param accountId The account ID from the user record in user-management.
     * @param authorities The authorities granted to the user.
     * @return An authenticated CustomUserPwdAuthenticationToken.
     */
    public static CustomUserPwdAuthenticationToken authenticated(Object principal, Object credentials,
                                                                 String accountName, String accountId,
                                                                 Collection<? extends GrantedAuthority> authorities) {
        return new CustomUserPwdAuthenticationToken(principal, credentials, accountName, accountId, authorities);
    }

    /**
     * Creates an authenticated token with account ID and per-user MFA override.
     *
     * @param principal The principal (user) making the request.
     * @param credentials The credentials of the user.
     * @param accountName The account name from the login request.
     * @param accountId The account ID from the user record in user-management.
     * @param mfaRequired Per-user MFA override from the {@code mfaRequired} user attribute;
     *                    {@code null} means no override — use normal step-up rules.
     * @param authorities The authorities granted to the user.
     * @return An authenticated CustomUserPwdAuthenticationToken.
     */
    public static CustomUserPwdAuthenticationToken authenticated(Object principal, Object credentials,
                                                                 String accountName, String accountId,
                                                                 Boolean mfaRequired,
                                                                 Collection<? extends GrantedAuthority> authorities) {
        return new CustomUserPwdAuthenticationToken(principal, credentials, accountName, accountId,
                mfaRequired, authorities);
    }

    /**
     * This method retrieves the account name of the user.
     *
     * @return The account name of the user.
     */
    public String getAccountName() {
        return this.accountName;
    }

    /**
     * Returns the account ID sourced from the user-management service record.
     *
     * @return The account ID of the user, or {@code null} if not available.
     */
    public String getAccountId() {
        return this.accountId;
    }

    /**
     * Returns the per-user MFA override sourced from the {@code mfaRequired} user attribute.
     * <ul>
     *   <li>{@code true}  – MFA is always required for this user in CONDITIONAL mode.</li>
     *   <li>{@code false} – MFA is explicitly exempted for this user in CONDITIONAL mode.</li>
     *   <li>{@code null}  – No per-user override; normal step-up evaluation applies.</li>
     * </ul>
     *
     * @return the per-user MFA required flag, or {@code null} if not set.
     */
    public Boolean getMfaRequired() {
        return this.mfaRequired;
    }

    /**
     * This method overrides the equals method from the superclass.
     * It checks if the object is an instance of CustomUserPwdAuthenticationToken and if the account names are equal.
     *
     * @param obj The object to compare with.
     * @return True if the objects are equal, false otherwise.
     */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CustomUserPwdAuthenticationToken token)) {
            return false;
        }
        if (this.getAccountName() == null && token.getAccountName() != null) {
            return false;
        }
        if (this.getAccountName() != null && !this.getAccountName().equals(token.getAccountName())) {
            return false;
        }
        return super.equals(token);
    }

    /**
     * This method overrides the hashCode method from the superclass.
     * It calculates the hash code based on the account name and the superclass's hash code.
     *
     * @return The hash code.
     */
    @Override
    public int hashCode() {
        int code = super.hashCode();
        if (this.getAccountName() != null) {
            code ^= this.getAccountName().hashCode();
        }
        return code;
    }

    /**
     * This method overrides the toString method from the superclass.
     * It returns a string representation of the CustomUserPwdAuthenticationToken.
     *
     * @return The string representation of the CustomUserPwdAuthenticationToken.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName()).append(" [");
        sb.append("Principal=").append(getPrincipal() != null ? getPrincipal() : "null").append(", ");
        sb.append("Credentials=[PROTECTED], ");
        sb.append("Account Name=").append(getAccountName() != null ? getAccountName() : "null").append(", ");
        sb.append("Account ID=").append(getAccountId() != null ? getAccountId() : "null").append(", ");
        sb.append("Authenticated=").append(isAuthenticated()).append(", ");
        sb.append("Details=").append(getDetails() != null ? getDetails() : "null").append(", ");
        sb.append("Granted Authorities=").append(getAuthorities() != null ? getAuthorities() : "null");
        sb.append("]");
        return sb.toString();
    }

}