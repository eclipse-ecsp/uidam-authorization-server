/*
 * Copyright (c) 2023-24 Harman International
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.oauth2.server.core.entities;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for {@link AuthorizationConsent} and {@link AuthorizationConsent.AuthorizationConsentId}.
 */
class AuthorizationConsentTest {

    private static final String CLIENT_ID = "test-client-id";
    private static final String PRINCIPAL = "test-principal";
    private static final String DIFFERENT_CLIENT_ID = "different-client-id";
    private static final String DIFFERENT_PRINCIPAL = "different-principal";

    @Test
    void testAuthorizationConsentIdConstructor() {
        AuthorizationConsent.AuthorizationConsentId id = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, PRINCIPAL);

        assertThat(id).isNotNull();
    }

    @Test
    void testAuthorizationConsentIdEqualsWithSameObject() {
        AuthorizationConsent.AuthorizationConsentId id = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, PRINCIPAL);

        assertThat(id).isEqualTo(id);
    }

    @Test
    void testAuthorizationConsentIdEqualsWithEqualObjects() {
        AuthorizationConsent.AuthorizationConsentId id1 = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, PRINCIPAL);
        AuthorizationConsent.AuthorizationConsentId id2 = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, PRINCIPAL);

        assertThat(id1).isEqualTo(id2);
        assertThat(id2).isEqualTo(id1);
    }

    @Test
    void testAuthorizationConsentIdEqualsWithDifferentClientId() {
        AuthorizationConsent.AuthorizationConsentId id1 = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, PRINCIPAL);
        AuthorizationConsent.AuthorizationConsentId id2 = 
            new AuthorizationConsent.AuthorizationConsentId(DIFFERENT_CLIENT_ID, PRINCIPAL);

        assertThat(id1).isNotEqualTo(id2);
    }

    @Test
    void testAuthorizationConsentIdEqualsWithDifferentPrincipal() {
        AuthorizationConsent.AuthorizationConsentId id1 = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, PRINCIPAL);
        AuthorizationConsent.AuthorizationConsentId id2 = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, DIFFERENT_PRINCIPAL);

        assertThat(id1).isNotEqualTo(id2);
    }

    @Test
    void testAuthorizationConsentIdEqualsWithNull() {
        AuthorizationConsent.AuthorizationConsentId id = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, PRINCIPAL);

        assertThat(id).isNotEqualTo(null);
    }

    @Test
    void testAuthorizationConsentIdEqualsWithDifferentClass() {
        AuthorizationConsent.AuthorizationConsentId id = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, PRINCIPAL);
        String differentType = "different-type";

        assertThat(id).isNotEqualTo(differentType);
    }

    @Test
    void testAuthorizationConsentIdHashCodeConsistency() {
        AuthorizationConsent.AuthorizationConsentId id1 = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, PRINCIPAL);
        AuthorizationConsent.AuthorizationConsentId id2 = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, PRINCIPAL);

        assertThat(id1.hashCode()).isEqualTo(id2.hashCode());
    }

    @Test
    void testAuthorizationConsentIdHashCodeWithDifferentValues() {
        AuthorizationConsent.AuthorizationConsentId id1 = 
            new AuthorizationConsent.AuthorizationConsentId(CLIENT_ID, PRINCIPAL);
        AuthorizationConsent.AuthorizationConsentId id2 = 
            new AuthorizationConsent.AuthorizationConsentId(DIFFERENT_CLIENT_ID, DIFFERENT_PRINCIPAL);

        assertThat(id1.hashCode()).isNotEqualTo(id2.hashCode());
    }

    @Test
    void testAuthorizationConsentGettersAndSetters() {
        AuthorizationConsent consent = new AuthorizationConsent();
        consent.setRegisteredClientId(CLIENT_ID);
        consent.setPrincipalName(PRINCIPAL);
        consent.setAuthorities("SCOPE_read SCOPE_write");

        assertThat(consent.getRegisteredClientId()).isEqualTo(CLIENT_ID);
        assertThat(consent.getPrincipalName()).isEqualTo(PRINCIPAL);
        assertThat(consent.getAuthorities()).isEqualTo("SCOPE_read SCOPE_write");
    }
}
