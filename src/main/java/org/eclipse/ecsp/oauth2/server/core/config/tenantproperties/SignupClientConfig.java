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

/**
 * Per-client signup configuration bound from {@code tenant.props.*.signup-config-list}.
 * Allows overriding the default assigned role and account for users who self-register
 * via a specific OAuth2 client.
 */
@Getter
@Setter
public class SignupClientConfig {

    /** OAuth2 client ID this configuration applies to. */
    private String clientId;

    /**
     * Comma-separated attribute names to hide from the sign-up form for this client.
     * Mirrors the legacy {@code signupSkipAttributes} stored in
     * {@code RegisteredClientDetails.additionalInformation}.
     */
    private String skipAttributes;

    /**
     * Comma-separated role name(s) to assign to the newly created user.
     * Overrides the tenant-level {@code user.default-role} when this client is used.
     */
    private String defaultRoles;

    /**
     * Account name to assign the new user to.
     * Overrides the user-management tenant-level {@code userDefaultAccountName}
     * when this client is used.
     */
    private String defaultAccount;

    /**
     * Comma-separated list of custom attribute mappings in the format
     * {@code attrKey#displayName} (e.g. {@code custom:companyName#companyName}).
     * Used both to auto-populate server-side attributes on sign-up and to control
     * which keys are included as JWT claims for this client.
     */
    private String customAttributeListMap;

    /**
     * Optional user status to assign at self-signup for this client
     * (e.g. {@code PENDING}, {@code ACTIVE}). When set, overrides the
     * tenant-level lifecycle/email-verification status logic in user-management.
     * Leave blank to use the default behaviour.
     */
    private String userStatus;

    /**
     * Comma-separated attribute keys whose values should be included as JWT claims
     * for tokens issued to this client (e.g.
     * {@code userName,email,ATTR_custom:companyName,ATTR_custom:companyAddress}).
     * Each key is resolved one of two ways:
     * <ul>
     *   <li>Prefixed with {@code ATTR_} — looked up (after stripping the prefix) in the
     *       user's dynamic custom attributes (from {@code user_attribute_values}).</li>
     *   <li>No prefix — resolved against the mandatory/core user fields
     *       (e.g. {@code id}, {@code userName}, {@code email}, {@code accountId},
     *       {@code status}, {@code tenantId}, {@code lastSuccessfulLoginTime},
     *       {@code mfaRequired}).</li>
     * </ul>
     * When blank or null no per-client custom attributes are added to claims.
     */
    private String customAttributesForClaims;
}
