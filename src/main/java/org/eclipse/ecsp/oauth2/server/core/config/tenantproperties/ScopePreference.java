/*
 * Copyright (c) 2023-24 Harman International
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

/**
 * Controls how external (IDP-mapped) roles and internal user scope are merged
 * when building the JWT token for a federated login.
 */
public enum ScopePreference {

    /**
     * Use only internal UIDAM scope from user-management.
     * IDP-derived scope mappings are ignored.
     * Default — fully backward-compatible with pre-existing tenants.
     */
    INTERNAL,

    /**
     * Use only the roles resolved from IDP claim mappings.
     * Internal scope stored in user-management are discarded for this login.
     */
    EXTERNAL,

    /**
     * Merge both internal scope and externally-mapped roles.
     * When mappings match, the mapped (external) value wins over internal scope.
     */
    BOTH
}
