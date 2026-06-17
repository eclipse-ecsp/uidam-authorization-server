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

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import lombok.Getter;
import lombok.Setter;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Per-tenant MFA (TOTP) enforcement policy.
 *
 * <p>Bound from tenant properties, e.g.:
 * <pre>
 * tenant.props.&lt;tenant&gt;.mfa.mode=CONDITIONAL
 * tenant.props.&lt;tenant&gt;.mfa.step-up-scopes=admin:write,billing:manage
 * tenant.props.&lt;tenant&gt;.mfa.skip-users=admin,svc-account
 * tenant.props.&lt;tenant&gt;.mfa.skip-clients=mobile-app,service-account-client
 * </pre>
 */
@Getter
@Setter
public class MfaPolicyProperties {

    /**
     * Tenant-wide MFA enforcement mode.
     */
    public enum MfaMode {
        /** MFA is never enforced for the tenant. */
        DISABLED,
        /** MFA is enforced only when the requested (or user) scopes intersect {@code stepUpScopes}. */
        CONDITIONAL,
        /** MFA is enforced for every internal-IDP user (subject to the skip-list). */
        REQUIRED
    }

    /**
     * Overall MFA enforcement mode for the tenant.
     * Defaults to {@link MfaMode#REQUIRED} to preserve the previous always-on behaviour.
     */
    private MfaMode mode = MfaMode.REQUIRED;

    /**
     * Comma-separated OAuth2 scopes that trigger an MFA step-up when {@link #mode} is
     * {@link MfaMode#CONDITIONAL}.  If the authorization request carries no scopes
     * (e.g. a portal login), the user's own granted scopes are checked instead.
     */
    private String stepUpScopes;

    /**
     * Comma-separated usernames that are exempt from MFA enforcement (e.g. {@code admin}).
     * Matching is case-insensitive.
     */
    private String skipUsers;

    /**
     * Comma-separated OAuth2 client IDs that are exempt from MFA enforcement in both
     * {@link MfaMode#REQUIRED} and {@link MfaMode#CONDITIONAL} modes
     * (e.g. {@code mobile-app,service-account-client}).
     * Matching is case-insensitive.  The client ID is read from the {@code client_id}
     * request parameter present on the {@code /oauth2/authorize} endpoint.
     * Has no effect when mode is {@link MfaMode#DISABLED} (MFA is already off).
     */
    private String skipClients;

    /**
     * Comma-separated account IDs that are exempt from MFA enforcement in both
     * {@link MfaMode#REQUIRED} and {@link MfaMode#CONDITIONAL} modes.
     * Matched against the account ID sourced from the user-management service record
     * (same origin as the user's granted scopes — not the login-form input).
     * Matching is case-insensitive.
     * Has no effect when mode is {@link MfaMode#DISABLED} (MFA is already off).
     */
    private String skipAccounts;

    /**
     * Comma-separated OAuth2 client IDs that trigger an MFA step-up when {@link #mode} is
     * {@link MfaMode#CONDITIONAL} (e.g. {@code admin-portal,ops-dashboard}).
     * Matching is case-insensitive.  Evaluated after skip-lists; if the requesting
     * client ID matches, MFA is enforced regardless of scope.
     */
    private String stepUpClients;

    /**
     * Comma-separated account IDs that trigger an MFA step-up when {@link #mode} is
     * {@link MfaMode#CONDITIONAL}.
     * Matched against the account ID sourced from the user-management service record
     * (same origin as the user's granted scopes — not the login-form input).
     * Matching is case-insensitive.  Evaluated after skip-lists; if the user's account ID
     * matches, MFA is enforced regardless of scope.
     */
    private String stepUpAccounts;

    /**
     * Parse {@link #stepUpScopes} into a set of trimmed, non-empty scope strings.
     *
     * @return the configured step-up scopes (never {@code null})
     */
    public Set<String> getStepUpScopeSet() {
        return toSet(stepUpScopes);
    }

    /**
     * Parse {@link #skipUsers} into a set of trimmed, non-empty usernames.
     *
     * @return the configured skip-list usernames (never {@code null})
     */
    public Set<String> getSkipUserSet() {
        return toSet(skipUsers);
    }

    /**
     * Parse {@link #skipClients} into a set of trimmed, non-empty client IDs.
     *
     * @return the configured skip-list client IDs (never {@code null})
     */
    public Set<String> getSkipClientSet() {
        return toSet(skipClients);
    }

    /**
     * Parse {@link #skipAccounts} into a set of trimmed, non-empty account names.
     *
     * @return the configured skip-list account names (never {@code null})
     */
    public Set<String> getSkipAccountSet() {
        return toSet(skipAccounts);
    }

    /**
     * Parse {@link #stepUpClients} into a set of trimmed, non-empty client IDs.
     *
     * @return the configured step-up client IDs (never {@code null})
     */
    public Set<String> getStepUpClientSet() {
        return toSet(stepUpClients);
    }

    /**
     * Parse {@link #stepUpAccounts} into a set of trimmed, non-empty account names.
     *
     * @return the configured step-up account names (never {@code null})
     */
    public Set<String> getStepUpAccountSet() {
        return toSet(stepUpAccounts);
    }

    /**
     * Determine whether the given username is in the MFA skip-list (case-insensitive).
     *
     * @param username the username to check
     * @return {@code true} if the user should be exempt from MFA
     */
    public boolean isUserSkipped(String username) {
        if (username == null || username.isBlank()) {
            return false;
        }
        return getSkipUserSet().stream().anyMatch(u -> u.equalsIgnoreCase(username));
    }

    /**
     * Determine whether the given OAuth2 client ID is in the MFA skip-list (case-insensitive).
     *
     * @param clientId the client ID to check
     * @return {@code true} if the client should be exempt from MFA enforcement
     */
    public boolean isClientSkipped(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return false;
        }
        return getSkipClientSet().stream().anyMatch(c -> c.equalsIgnoreCase(clientId));
    }

    /**
     * Determine whether the given account name is in the MFA skip-list (case-insensitive).
     *
     * @param accountName the account name to check
     * @return {@code true} if the account should be exempt from MFA enforcement
     */
    public boolean isAccountSkipped(String accountName) {
        if (accountName == null || accountName.isBlank()) {
            return false;
        }
        return getSkipAccountSet().stream().anyMatch(a -> a.equalsIgnoreCase(accountName));
    }

    private static Set<String> toSet(String csv) {
        if (csv == null || csv.isBlank()) {
            return Collections.emptySet();
        }
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }
}
