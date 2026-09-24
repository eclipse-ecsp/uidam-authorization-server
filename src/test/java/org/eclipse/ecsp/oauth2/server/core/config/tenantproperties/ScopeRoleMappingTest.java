/*
 * Copyright (c) 2023-24 Harman International
 * Licensed under the Apache License, Version 2.0
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link ScopeRoleMapping}'s {@code ,}-delimited value parsing.
 */
class ScopeRoleMappingTest {

    @Test
    void getExternalRoleValues_nullValue_returnsEmptySet() {
        ScopeRoleMapping mapping = new ScopeRoleMapping();
        assertTrue(mapping.getExternalRoleValues().isEmpty());
    }

    @Test
    void getExternalRoleValues_blankValue_returnsEmptySet() {
        ScopeRoleMapping mapping = new ScopeRoleMapping();
        mapping.setExternalRoles("   ");
        assertTrue(mapping.getExternalRoleValues().isEmpty());
    }

    @Test
    void getExternalRoleValues_singleValue_returnsSingleton() {
        ScopeRoleMapping mapping = new ScopeRoleMapping();
        mapping.setExternalRoles("VWAG_STORE_PRE_GROUP_DEV");
        assertEquals(Set.of("VWAG_STORE_PRE_GROUP_DEV"), mapping.getExternalRoleValues());
    }

    @Test
    void getExternalRoleValues_multipleValues_splitsOnDelimiter() {
        ScopeRoleMapping mapping = new ScopeRoleMapping();
        mapping.setExternalRoles("VWAG_STORE_PRE_GROUP_DEV,VWAG_STORE_PRE_GROUP_DEVELPER");
        assertEquals(Set.of("VWAG_STORE_PRE_GROUP_DEV", "VWAG_STORE_PRE_GROUP_DEVELPER"),
                mapping.getExternalRoleValues());
    }

    @Test
    void getExternalRoleValues_trimsWhitespaceAroundEachToken() {
        ScopeRoleMapping mapping = new ScopeRoleMapping();
        mapping.setExternalRoles(" VWAG_STORE_PRE_GROUP_DEV , VWAG_STORE_PRE_GROUP_DEVELPER ");
        assertEquals(Set.of("VWAG_STORE_PRE_GROUP_DEV", "VWAG_STORE_PRE_GROUP_DEVELPER"),
                mapping.getExternalRoleValues());
    }

    @Test
    void getExternalRoleValues_filtersOutEmptyTokens() {
        ScopeRoleMapping mapping = new ScopeRoleMapping();
        mapping.setExternalRoles("VWAG_STORE_PRE_GROUP_DEV,,VWAG_STORE_PRE_GROUP_DEVELPER");
        assertEquals(Set.of("VWAG_STORE_PRE_GROUP_DEV", "VWAG_STORE_PRE_GROUP_DEVELPER"),
                mapping.getExternalRoleValues());
    }

    @Test
    void getInternalScopeValues_nullValue_returnsEmptySet() {
        ScopeRoleMapping mapping = new ScopeRoleMapping();
        assertTrue(mapping.getInternalScopeValues().isEmpty());
    }

    @Test
    void getInternalScopeValues_multipleValues_splitsOnDelimiter() {
        ScopeRoleMapping mapping = new ScopeRoleMapping();
        mapping.setInternalScopes("IgniteStoreSeller,igniteStorePortfolioManager");
        assertEquals(Set.of("IgniteStoreSeller", "igniteStorePortfolioManager"),
                mapping.getInternalScopeValues());
    }
}
