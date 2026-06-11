/********************************************************************************
 *
 * <p>
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
 *******************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.mfa;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for MfaPendingAuthenticationToken.
 */
class MfaPendingAuthenticationTokenTest {

    private static final String USERNAME = "testuser";

    // ─────────────── Constructor and core properties ──────────────────────────

    @Test
    void constructor_setsUsernameAndAuthorities() {
        Collection<SimpleGrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_USER"));
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(USERNAME, authorities);

        assertEquals(USERNAME, token.getPrincipal());
        assertFalse(token.isAuthenticated());
    }

    @Test
    void constructor_withEmptyAuthorities_createsToken() {
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());

        assertEquals(USERNAME, token.getPrincipal());
    }

    @Test
    void constructor_withNullUsername_createsToken() {
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(
                null, Collections.emptyList());

        assertNull(token.getPrincipal());
    }

    // ─────────────── isAuthenticated ─────────────────────────────────────────

    @Test
    void isAuthenticated_alwaysReturnsFalse() {
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());

        assertFalse(token.isAuthenticated());
    }

    @Test
    void setAuthenticated_trueDoesNotThrowByDefault() {
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());

        // AbstractAuthenticationToken allows setAuthenticated(true) for new tokens
        token.setAuthenticated(true);
        assertTrue(token.isAuthenticated());
    }

    @Test
    void setAuthenticated_falseDoesNotThrow() {
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());

        token.setAuthenticated(false); // Should not throw
        assertFalse(token.isAuthenticated());
    }

    // ─────────────── getCredentials ──────────────────────────────────────────

    @Test
    void getCredentials_returnsNull() {
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());

        assertNull(token.getCredentials());
    }

    // ─────────────── getPendingAuthorities ───────────────────────────────────

    @Test
    void getPendingAuthorities_returnsSuppliedAuthorities() {
        List<SimpleGrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_ADMIN"));
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(USERNAME, authorities);

        Collection<?> pending = token.getPendingAuthorities();
        assertEquals(2, pending.size());
    }

    @Test
    void getPendingAuthorities_withEmptyList_returnsEmpty() {
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());

        Collection<?> pending = token.getPendingAuthorities();
        assertTrue(pending.isEmpty());
    }

    // ─────────────── equals and hashCode ─────────────────────────────────────

    @Test
    void equals_sameUsernameAndAuthorities_returnsTrue() {
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        MfaPendingAuthenticationToken token1 = new MfaPendingAuthenticationToken(USERNAME, authorities);
        MfaPendingAuthenticationToken token2 = new MfaPendingAuthenticationToken(USERNAME, authorities);

        assertEquals(token1, token2);
    }

    @Test
    void equals_differentUsername_returnsFalse() {
        MfaPendingAuthenticationToken token1 = new MfaPendingAuthenticationToken(
                "user1", Collections.emptyList());
        MfaPendingAuthenticationToken token2 = new MfaPendingAuthenticationToken(
                "user2", Collections.emptyList());

        assertNotEquals(token1, token2);
    }

    @Test
    void equals_sameObject_returnsTrue() {
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());

        assertEquals(token, token);
    }

    @Test
    void equals_nullObject_returnsFalse() {
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());

        assertNotEquals(null, token);
    }

    @Test
    void equals_differentType_returnsFalse() {
        MfaPendingAuthenticationToken token = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());

        assertNotEquals("someString", token);
    }

    @Test
    void hashCode_consistentForEqualTokens() {
        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        MfaPendingAuthenticationToken token1 = new MfaPendingAuthenticationToken(USERNAME, authorities);
        MfaPendingAuthenticationToken token2 = new MfaPendingAuthenticationToken(USERNAME, authorities);

        assertEquals(token1.hashCode(), token2.hashCode());
    }

    @Test
    void hashCode_differentForDifferentUsers() {
        MfaPendingAuthenticationToken token1 = new MfaPendingAuthenticationToken(
                "user1", Collections.emptyList());
        MfaPendingAuthenticationToken token2 = new MfaPendingAuthenticationToken(
                "user2", Collections.emptyList());

        assertNotEquals(token1.hashCode(), token2.hashCode());
    }
}
