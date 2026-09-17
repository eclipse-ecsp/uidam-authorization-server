/*******************************************************************************
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

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Unit tests for {@link SignupClientConfig}.
 * Verifies getter/setter round-trips for all six fields introduced in the
 * per-client signup customisation feature.
 */
class SignupClientConfigTest {

    // -----------------------------------------------------------------------
    // clientId
    // -----------------------------------------------------------------------

    @Test
    void getSetClientId_roundTrip() {
        SignupClientConfig config = new SignupClientConfig();
        assertNull(config.getClientId());
        config.setClientId("test-portal");
        assertEquals("test-portal", config.getClientId());
    }

    // -----------------------------------------------------------------------
    // skipAttributes
    // -----------------------------------------------------------------------

    @Test
    void getSetSkipAttributes_roundTrip() {
        SignupClientConfig config = new SignupClientConfig();
        assertNull(config.getSkipAttributes());
        config.setSkipAttributes("hasValidPassport,age");
        assertEquals("hasValidPassport,age", config.getSkipAttributes());
    }

    // -----------------------------------------------------------------------
    // defaultRoles
    // -----------------------------------------------------------------------

    @Test
    void getSetDefaultRoles_roundTrip() {
        SignupClientConfig config = new SignupClientConfig();
        assertNull(config.getDefaultRoles());
        config.setDefaultRoles("VEHICLE_OWNER,GUEST");
        assertEquals("VEHICLE_OWNER,GUEST", config.getDefaultRoles());
    }

    // -----------------------------------------------------------------------
    // defaultAccount
    // -----------------------------------------------------------------------

    @Test
    void getSetDefaultAccount_roundTrip() {
        SignupClientConfig config = new SignupClientConfig();
        assertNull(config.getDefaultAccount());
        config.setDefaultAccount("userdefaultaccount");
        assertEquals("userdefaultaccount", config.getDefaultAccount());
    }

    // -----------------------------------------------------------------------
    // customAttributeListMap
    // -----------------------------------------------------------------------

    @Test
    void getSetCustomAttributeListMap_roundTrip() {
        SignupClientConfig config = new SignupClientConfig();
        assertNull(config.getCustomAttributeListMap());
        config.setCustomAttributeListMap("custom:companyName#Acme,custom:companyAddress#123 Main St");
        assertEquals("custom:companyName#Acme,custom:companyAddress#123 Main St",
                config.getCustomAttributeListMap());
    }

    @Test
    void getSetCustomAttributeListMap_emptyString() {
        SignupClientConfig config = new SignupClientConfig();
        config.setCustomAttributeListMap("");
        assertEquals("", config.getCustomAttributeListMap());
    }

    // -----------------------------------------------------------------------
    // userStatus
    // -----------------------------------------------------------------------

    @Test
    void getSetUserStatus_roundTrip() {
        SignupClientConfig config = new SignupClientConfig();
        assertNull(config.getUserStatus());
        config.setUserStatus("PENDING");
        assertEquals("PENDING", config.getUserStatus());
    }

    @Test
    void getSetUserStatus_emptyString() {
        SignupClientConfig config = new SignupClientConfig();
        config.setUserStatus("");
        assertEquals("", config.getUserStatus());
    }

    @Test
    void getSetUserStatus_active() {
        SignupClientConfig config = new SignupClientConfig();
        config.setUserStatus("ACTIVE");
        assertEquals("ACTIVE", config.getUserStatus());
    }

    // -----------------------------------------------------------------------
    // customAttributesForClaims
    // -----------------------------------------------------------------------

    @Test
    void getSetCustomAttributesForClaims_roundTrip() {
        SignupClientConfig config = new SignupClientConfig();
        assertNull(config.getCustomAttributesForClaims());
        config.setCustomAttributesForClaims("custom:companyName,signupSourceClientId");
        assertEquals("custom:companyName,signupSourceClientId", config.getCustomAttributesForClaims());
    }

    @Test
    void getSetCustomAttributesForClaims_emptyString() {
        SignupClientConfig config = new SignupClientConfig();
        config.setCustomAttributesForClaims("");
        assertEquals("", config.getCustomAttributesForClaims());
    }

    @Test
    void getSetCustomAttributesForClaims_overwrite() {
        SignupClientConfig config = new SignupClientConfig();
        config.setCustomAttributesForClaims("key1");
        config.setCustomAttributesForClaims("key2,key3");
        assertEquals("key2,key3", config.getCustomAttributesForClaims());
    }

    // -----------------------------------------------------------------------
    // Multiple fields on same instance
    // -----------------------------------------------------------------------

    @Test
    void allFields_setThenGet() {
        SignupClientConfig config = new SignupClientConfig();
        config.setClientId("portal-a");
        config.setSkipAttributes("attr1,attr2");
        config.setDefaultRoles("ROLE_A");
        config.setDefaultAccount("accountB");
        config.setCustomAttributeListMap("key1#val1");
        config.setUserStatus("PENDING");
        config.setCustomAttributesForClaims("custom:companyName,signupSourceClientId");

        assertEquals("portal-a", config.getClientId());
        assertEquals("attr1,attr2", config.getSkipAttributes());
        assertEquals("ROLE_A", config.getDefaultRoles());
        assertEquals("accountB", config.getDefaultAccount());
        assertEquals("key1#val1", config.getCustomAttributeListMap());
        assertEquals("PENDING", config.getUserStatus());
        assertEquals("custom:companyName,signupSourceClientId", config.getCustomAttributesForClaims());
    }

    @Test
    void overwrite_field_returnsFinalValue() {
        SignupClientConfig config = new SignupClientConfig();
        config.setUserStatus("PENDING");
        config.setUserStatus("ACTIVE");
        assertEquals("ACTIVE", config.getUserStatus());
    }
}
