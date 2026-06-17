/*******************************************************************************
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

package org.eclipse.ecsp.oauth2.server.core.authentication.tokens;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for CustomUserPwdAuthenticationTokenDeserializer.
 */
class CustomUserPwdAuthenticationTokenDeserializerTest {

    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        SimpleModule module = new SimpleModule();
        module.addDeserializer(CustomUserPwdAuthenticationToken.class,
                new CustomUserPwdAuthenticationTokenDeserializer());
        objectMapper.registerModule(module);
    }

    @Test
    void deserialize_authenticatedToken_returnsAuthenticatedToken() throws Exception {
        String json = "{"
                + "\"authenticated\": true,"
                + "\"principal\": \"user123\","
                + "\"credentials\": \"password\","
                + "\"accountName\": \"myAccount\","
                + "\"authorities\": []"
                + "}";

        CustomUserPwdAuthenticationToken token = objectMapper.readValue(json,
                CustomUserPwdAuthenticationToken.class);

        assertNotNull(token);
        assertTrue(token.isAuthenticated());
        assertEquals("user123", token.getPrincipal());
        assertEquals("password", token.getCredentials());
        assertEquals("myAccount", token.getAccountName());
        assertTrue(token.getAuthorities().isEmpty());
    }

    @Test
    void deserialize_unauthenticatedToken_returnsUnauthenticatedToken() throws Exception {
        String json = "{"
                + "\"authenticated\": false,"
                + "\"principal\": \"user123\","
                + "\"credentials\": \"password\","
                + "\"accountName\": \"myAccount\","
                + "\"authorities\": []"
                + "}";

        CustomUserPwdAuthenticationToken token = objectMapper.readValue(json,
                CustomUserPwdAuthenticationToken.class);

        assertNotNull(token);
        assertFalse(token.isAuthenticated());
    }

    @Test
    void deserialize_nullCredentials_returnsNullCredentials() throws Exception {
        String json = "{"
                + "\"authenticated\": false,"
                + "\"principal\": \"user123\","
                + "\"credentials\": null,"
                + "\"accountName\": \"myAccount\","
                + "\"authorities\": []"
                + "}";

        CustomUserPwdAuthenticationToken token = objectMapper.readValue(json,
                CustomUserPwdAuthenticationToken.class);

        assertNotNull(token);
        assertNull(token.getCredentials());
    }

    @Test
    void deserialize_nullAccountName_returnsNullAccountName() throws Exception {
        String json = "{"
                + "\"authenticated\": false,"
                + "\"principal\": \"user123\","
                + "\"credentials\": \"password\","
                + "\"accountName\": null,"
                + "\"authorities\": []"
                + "}";

        CustomUserPwdAuthenticationToken token = objectMapper.readValue(json,
                CustomUserPwdAuthenticationToken.class);

        assertNotNull(token);
        assertNull(token.getAccountName());
    }

    @Test
    void deserialize_nullDetails_setsDetailsToNull() throws Exception {
        String json = "{"
                + "\"authenticated\": true,"
                + "\"principal\": \"user123\","
                + "\"credentials\": \"pass\","
                + "\"accountName\": \"acc\","
                + "\"authorities\": [],"
                + "\"details\": null"
                + "}";

        CustomUserPwdAuthenticationToken token = objectMapper.readValue(json,
                CustomUserPwdAuthenticationToken.class);

        assertNotNull(token);
        assertNull(token.getDetails());
    }

    @Test
    void deserialize_withDetails_setsDetailsObject() throws Exception {
        String json = "{"
                + "\"authenticated\": true,"
                + "\"principal\": \"user123\","
                + "\"credentials\": \"pass\","
                + "\"accountName\": \"acc\","
                + "\"authorities\": [],"
                + "\"details\": {\"key\": \"value\"}"
                + "}";

        CustomUserPwdAuthenticationToken token = objectMapper.readValue(json,
                CustomUserPwdAuthenticationToken.class);

        assertNotNull(token);
        assertNotNull(token.getDetails());
    }

    @Test
    void deserialize_missingOptionalFields_usesMissingNodeDefaults() throws Exception {
        // Only required fields; optional principal, credentials, accountName, details are absent
        String json = "{"
                + "\"authenticated\": false,"
                + "\"authorities\": []"
                + "}";

        CustomUserPwdAuthenticationToken token = objectMapper.readValue(json,
                CustomUserPwdAuthenticationToken.class);

        assertNotNull(token);
        assertFalse(token.isAuthenticated());
    }

    @Test
    void deserialize_numericCredentials_returnsNullCredentials() throws Exception {
        // Non-textual (numeric) credentials node → getCredentials returns null
        String json = "{"
                + "\"authenticated\": false,"
                + "\"principal\": \"user123\","
                + "\"credentials\": 12345,"
                + "\"accountName\": \"acc\","
                + "\"authorities\": []"
                + "}";

        CustomUserPwdAuthenticationToken token = objectMapper.readValue(json,
                CustomUserPwdAuthenticationToken.class);

        assertNotNull(token);
        assertNull(token.getCredentials());
    }

    @Test
    void deserialize_numericAccountName_returnsNullAccountName() throws Exception {
        // Non-textual (numeric) accountName node → getAccountName returns null
        String json = "{"
                + "\"authenticated\": false,"
                + "\"principal\": \"user123\","
                + "\"credentials\": \"pass\","
                + "\"accountName\": 99999,"
                + "\"authorities\": []"
                + "}";

        CustomUserPwdAuthenticationToken token = objectMapper.readValue(json,
                CustomUserPwdAuthenticationToken.class);

        assertNotNull(token);
        assertNull(token.getAccountName());
    }

    @Test
    void deserialize_objectPrincipal_returnsNullPrincipal() throws Exception {
        // Non-textual principal node → getPrincipal returns null (due to !isTextual() check)
        String json = "{"
                + "\"authenticated\": false,"
                + "\"principal\": {\"name\": \"user123\"},"
                + "\"credentials\": \"pass\","
                + "\"accountName\": \"acc\","
                + "\"authorities\": []"
                + "}";

        CustomUserPwdAuthenticationToken token = objectMapper.readValue(json,
                CustomUserPwdAuthenticationToken.class);

        assertNotNull(token);
        // Object principal returns null from getPrincipal (per source logic)
        assertNull(token.getPrincipal());
    }

    @Test
    void deserialize_missingDetailsField_setsDetailsToNull() throws Exception {
        // No "details" field → MissingNode → details set to null
        String json = "{"
                + "\"authenticated\": true,"
                + "\"principal\": \"user123\","
                + "\"credentials\": \"pass\","
                + "\"accountName\": \"acc\","
                + "\"authorities\": []"
                + "}";

        CustomUserPwdAuthenticationToken token = objectMapper.readValue(json,
                CustomUserPwdAuthenticationToken.class);

        assertNotNull(token);
        assertNull(token.getDetails());
    }
}
