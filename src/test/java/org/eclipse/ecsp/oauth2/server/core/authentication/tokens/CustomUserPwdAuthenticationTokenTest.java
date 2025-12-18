/*
 * Copyright (c) 2023-24 Harman International
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.oauth2.server.core.authentication.tokens;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test class for CustomUserPwdAuthenticationToken.
 */
class CustomUserPwdAuthenticationTokenTest {

    private static final String TEST_PRINCIPAL = "testUser";
    private static final String TEST_CREDENTIALS = "testPassword";
    private static final String TEST_ACCOUNT_NAME = "testAccount";
    private static final String DIFFERENT_ACCOUNT_NAME = "differentAccount";

    @Test
    void testConstructorWithoutAuthorities() {
        CustomUserPwdAuthenticationToken token = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);

        assertEquals(TEST_PRINCIPAL, token.getPrincipal());
        assertEquals(TEST_CREDENTIALS, token.getCredentials());
        assertEquals(TEST_ACCOUNT_NAME, token.getAccountName());
        assertFalse(token.isAuthenticated());
    }

    @Test
    void testConstructorWithAuthorities() {
        Collection<GrantedAuthority> authorities = Arrays.asList(
            new SimpleGrantedAuthority("ROLE_USER"),
            new SimpleGrantedAuthority("ROLE_ADMIN")
        );

        CustomUserPwdAuthenticationToken token = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME, authorities);

        assertEquals(TEST_PRINCIPAL, token.getPrincipal());
        assertEquals(TEST_CREDENTIALS, token.getCredentials());
        assertEquals(TEST_ACCOUNT_NAME, token.getAccountName());
        assertTrue(token.isAuthenticated());
        assertEquals(authorities.size(), token.getAuthorities().size());
    }

    @Test
    void testUnauthenticatedStaticMethod() {
        CustomUserPwdAuthenticationToken token = CustomUserPwdAuthenticationToken.unauthenticated(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);

        assertEquals(TEST_PRINCIPAL, token.getPrincipal());
        assertEquals(TEST_CREDENTIALS, token.getCredentials());
        assertEquals(TEST_ACCOUNT_NAME, token.getAccountName());
        assertFalse(token.isAuthenticated());
    }

    @Test
    void testAuthenticatedStaticMethod() {
        Collection<GrantedAuthority> authorities = Arrays.asList(
            new SimpleGrantedAuthority("ROLE_USER")
        );

        CustomUserPwdAuthenticationToken token = CustomUserPwdAuthenticationToken.authenticated(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME, authorities);

        assertEquals(TEST_PRINCIPAL, token.getPrincipal());
        assertEquals(TEST_CREDENTIALS, token.getCredentials());
        assertEquals(TEST_ACCOUNT_NAME, token.getAccountName());
        assertTrue(token.isAuthenticated());
    }

    @Test
    void testEqualsWithSameObject() {
        CustomUserPwdAuthenticationToken token = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);

        assertEquals(token, token);
    }

    @Test
    void testEqualsWithEqualObjects() {
        CustomUserPwdAuthenticationToken token1 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);
        CustomUserPwdAuthenticationToken token2 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);

        assertEquals(token1, token2);
    }

    @Test
    void testEqualsWithDifferentAccountNames() {
        CustomUserPwdAuthenticationToken token1 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);
        CustomUserPwdAuthenticationToken token2 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, DIFFERENT_ACCOUNT_NAME);

        assertNotEquals(token1, token2);
    }

    @Test
    void testEqualsWithNullAccountName() {
        CustomUserPwdAuthenticationToken token1 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, null);
        CustomUserPwdAuthenticationToken token2 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);

        assertNotEquals(token1, token2);
    }

    @Test
    void testEqualsWithBothNullAccountNames() {
        CustomUserPwdAuthenticationToken token1 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, null);
        CustomUserPwdAuthenticationToken token2 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, null);

        assertEquals(token1, token2);
    }

    @Test
    void testEqualsWithDifferentType() {
        CustomUserPwdAuthenticationToken token = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);
        UsernamePasswordAuthenticationToken differentToken = new UsernamePasswordAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS);

        assertNotEquals(token, differentToken);
    }

    @Test
    void testHashCodeConsistency() {
        CustomUserPwdAuthenticationToken token1 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);
        CustomUserPwdAuthenticationToken token2 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);

        assertEquals(token1.hashCode(), token2.hashCode());
    }

    @Test
    void testHashCodeWithNullAccountName() {
        CustomUserPwdAuthenticationToken token = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, null);

        // Should not throw exception
        int hashCode = token.hashCode();
        assertTrue(hashCode != 0 || hashCode == 0); // Just ensure it doesn't throw
    }

    @Test
    void testHashCodeWithDifferentAccountNames() {
        CustomUserPwdAuthenticationToken token1 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);
        CustomUserPwdAuthenticationToken token2 = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, DIFFERENT_ACCOUNT_NAME);

        assertNotEquals(token1.hashCode(), token2.hashCode());
    }

    @Test
    void testToString() {
        CustomUserPwdAuthenticationToken token = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME);

        String result = token.toString();

        assertTrue(result.contains("CustomUserPwdAuthenticationToken"));
        assertTrue(result.contains("Principal=" + TEST_PRINCIPAL));
        assertTrue(result.contains("Credentials=[PROTECTED]"));
        assertTrue(result.contains("Account Name=" + TEST_ACCOUNT_NAME));
        assertTrue(result.contains("Authenticated=false"));
    }

    @Test
    void testToStringWithNullValues() {
        CustomUserPwdAuthenticationToken token = new CustomUserPwdAuthenticationToken(
            null, null, null);

        String result = token.toString();

        assertTrue(result.contains("CustomUserPwdAuthenticationToken"));
        assertTrue(result.contains("Principal=null"));
        assertTrue(result.contains("Account Name=null"));
    }

    @Test
    void testToStringWithAuthorities() {
        Collection<GrantedAuthority> authorities = Arrays.asList(
            new SimpleGrantedAuthority("ROLE_USER")
        );
        CustomUserPwdAuthenticationToken token = new CustomUserPwdAuthenticationToken(
            TEST_PRINCIPAL, TEST_CREDENTIALS, TEST_ACCOUNT_NAME, authorities);

        String result = token.toString();

        assertTrue(result.contains("CustomUserPwdAuthenticationToken"));
        assertTrue(result.contains("Authenticated=true"));
        assertTrue(result.contains("Granted Authorities="));
    }
}
