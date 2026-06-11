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
