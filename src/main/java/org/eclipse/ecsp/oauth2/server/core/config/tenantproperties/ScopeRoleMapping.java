/*
 * Copyright (c) 2023-24 Harman International
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import lombok.Getter;
import lombok.Setter;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Represents a single external IDP role → internal UIDAM scope mapping rule.
 *
 * <p>Property binding example:
 * <pre>
 *   ...scopeRoleMappings[0].internalScopes=ManageUsers
 *   ...scopeRoleMappings[0].externalRoles=IDP_TEST_ADMIN,IDP_TEST_ADMIN_V2
 *   ...scopeRoleMappings[0].scopePreference=INTERNAL
 * </pre>
 *
 * <p>The {@code ,} character separates multiple values (logical OR on the
 * external side; all scopes are granted on the internal side).
 */
@Getter
@Setter
public class ScopeRoleMapping {

    private static final String IDP_CLAIM_DELIMITER = ",";

    /**
     * Internal UIDAM scope(s) to grant when any of the external IDP role values match.
     * Supports multiple scopes separated by {@code ,},
     * e.g. {@code ManageUsers,ViewUsers}.
     */
    private String internalScopes;

    /**
     * External IDP role/group value(s) that trigger this mapping.
     * Multiple values separated by {@code ,} are treated as logical OR,
     * e.g. {@code VWAG_STORE_PRE_GROUP_DEV,VWAG_STORE_GROUP_DEVELOPER}.
     */
    private String externalRoles;

    /**
     * Returns the set of external IDP role values parsed from {@link #externalRoles}.
     *
     * @return immutable set of trimmed, non-empty values; never null
     */
    public Set<String> getExternalRoleValues() {
        return parseDelimited(externalRoles);
    }

    /**
     * Returns the set of internal UIDAM scope names parsed from {@link #internalScopes}.
     *
     * @return immutable set of trimmed, non-empty scope names; never null
     */
    public Set<String> getInternalScopeValues() {
        return parseDelimited(internalScopes);
    }

    private Set<String> parseDelimited(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.split(IDP_CLAIM_DELIMITER))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }
}