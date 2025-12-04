/********************************************************************************
 * Copyright (c) 2024-25 Harman International 
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

package org.eclipse.ecsp.audit.util;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for PiiMasker.
 */
class PiiMaskerTest {

    private static final String MASKED = "***MASKED***";

    @Test
    void maskJsonShouldMaskUsernameField() {
        // Given
        String json = "{\"username\":\"john.doe\",\"userId\":\"123\"}";

        // When
        String masked = PiiMasker.maskJson(json);

        // Then - username should be partially masked (show first 2 + last 2 chars)
        assertThat(masked).contains("jo***oe");
        assertThat(masked).contains("userId");
        assertThat(masked).contains("123");
        assertThat(masked).doesNotContain("john.doe");
    }

    @Test
    void maskJsonShouldMaskEmailField() {
        // Given
        String json = "{\"email\":\"user@example.com\",\"id\":\"456\"}";

        // When
        String masked = PiiMasker.maskJson(json);

        // Then - email should be partially masked (show first chars + domain)
        assertThat(masked).contains("us***@example.com");
        assertThat(masked).doesNotContain("user@example.com");
    }

    @Test
    void maskJsonShouldMaskPasswordField() {
        // Given
        String json = "{\"password\":\"secretPassword123\",\"username\":\"alice\"}";

        // When
        String masked = PiiMasker.maskJson(json);

        // Then - password fully masked, username partially masked
        assertThat(masked).contains(MASKED);
        assertThat(masked).doesNotContain("secretPassword123");
        assertThat(masked).doesNotContain("alice");
        // Note: alice is 5 chars, so shows al***ce (first 2 + last 2)
        assertThat(masked).contains("al***ce");
    }

    @Test
    void maskJsonShouldMaskTokenFields() {
        // Given
        String json = "{\"accessToken\":\"abc123\",\"refreshToken\":\"xyz789\"}";

        // When
        String masked = PiiMasker.maskJson(json);

        // Then
        assertThat(masked).contains(MASKED);
        assertThat(masked).doesNotContain("abc123");
        assertThat(masked).doesNotContain("xyz789");
    }

    @Test
    void maskJsonShouldNotMaskNonPiiFields() {
        // Given
        String json = "{\"userId\":\"123\",\"clientId\":\"app-client\",\"tenantId\":\"tenant1\"}";

        // When
        String masked = PiiMasker.maskJson(json);

        // Then
        assertThat(masked).contains("123");
        assertThat(masked).contains("app-client");
        assertThat(masked).contains("tenant1");
        assertThat(masked).doesNotContain(MASKED);
    }

    @Test
    void maskJsonWithNullShouldReturnNull() {
        // When
        String masked = PiiMasker.maskJson(null);

        // Then
        assertThat(masked).isNull();
    }

    @Test
    void maskJsonWithEmptyStringShouldReturnNull() {
        // When
        String masked = PiiMasker.maskJson("");

        // Then
        assertThat(masked).isNull();
    }

    @Test
    void maskJsonWithInvalidJsonShouldReturnOriginal() {
        // Given
        String invalidJson = "not-a-json";

        // When
        String masked = PiiMasker.maskJson(invalidJson);

        // Then
        assertThat(masked).isEqualTo(invalidJson);
    }

    @Test
    void maskAndSerializeShouldMaskPiiFieldsInMap() {
        // Given
        Map<String, Object> map = new HashMap<>();
        map.put("username", "bobsmith");
        map.put("userId", "789");
        map.put("email", "bob@test.com");

        // When
        String masked = PiiMasker.maskAndSerialize(map);

        // Then - username shows first 2 + last 2, email shows first chars + domain
        assertThat(masked).contains("bo***th"); // First 2 + last 2 of bobsmith
        assertThat(masked).contains("bo***@test.com"); // First 3 + domain
        assertThat(masked).contains("789");
        assertThat(masked).doesNotContain("bobsmith");
    }

    @Test
    void maskAndSerializeWithNullMapShouldReturnNull() {
        // When
        String masked = PiiMasker.maskAndSerialize(null);

        // Then
        assertThat(masked).isNull();
    }

    @Test
    void maskAndSerializeWithEmptyMapShouldReturnNull() {
        // Given
        Map<String, Object> emptyMap = new HashMap<>();

        // When
        String masked = PiiMasker.maskAndSerialize(emptyMap);

        // Then
        assertThat(masked).isNull();
    }

    @Test
    void maskAndSerializeShouldHandleNestedObjects() {
        // Given
        Map<String, Object> nested = new HashMap<>();
        nested.put("email", "nested@test.com");
        nested.put("role", "admin");

        Map<String, Object> map = new HashMap<>();
        map.put("userId", "111");
        map.put("userDetails", nested);

        // When
        String masked = PiiMasker.maskAndSerialize(map);

        // Then - email shows first chars + domain
        assertThat(masked).contains("111");
        assertThat(masked).contains("admin");
        assertThat(masked).contains("nes***@test.com");
        assertThat(masked).doesNotContain("nested@test.com");
    }

    @Test
    void maskAndSerializeShouldMaskPhoneNumberField() {
        // Given
        Map<String, Object> map = new HashMap<>();
        map.put("phoneNumber", "+1234567890");
        map.put("userId", "222");

        // When
        String masked = PiiMasker.maskAndSerialize(map);

        // Then - phone shows last 4 digits only
        assertThat(masked).contains("******7890");
        assertThat(masked).doesNotContain("+1234567890");
    }

    @Test
    void maskAndSerializeShouldMaskAccountNameField() {
        // Given
        Map<String, Object> map = new HashMap<>();
        map.put("accountName", "John Doe");
        map.put("accountId", "acc-123");

        // When
        String masked = PiiMasker.maskAndSerialize(map);

        // Then - accountName shows first 2 + last 2 (treated like username)
        assertThat(masked).contains("Jo***oe");
        assertThat(masked).contains("acc-123");
        assertThat(masked).doesNotContain("John Doe");
    }

    @Test
    void maskAndSerializeShouldHandleMultiplePiiFields() {
        // Given
        Map<String, Object> map = new HashMap<>();
        map.put("username", "testuser");
        map.put("email", "test@example.com");
        map.put("phoneNumber", "555-1234");
        map.put("accountName", "Test User");
        map.put("userId", "333");

        // When
        String masked = PiiMasker.maskAndSerialize(map);

        // Then - all PII fields with field-specific masking
        assertThat(masked).contains("333");
        assertThat(masked).contains("te***er"); // First 2 + last 2 of testuser
        assertThat(masked).contains("te***@example.com"); // First 3 + domain
        assertThat(masked).contains("******1234"); // Last 4 digits of phone
        assertThat(masked).contains("Te***er"); // First 2 + last 2 of Test User
        assertThat(masked).doesNotContain("testuser");
        assertThat(masked).doesNotContain("555-1234");
        assertThat(masked).doesNotContain("Test User");
    }

    @Test
    void maskAndSerializeShouldMaskVinField() {
        // Given
        Map<String, Object> map = new HashMap<>();
        map.put("vin", "ABC12345678901234");
        map.put("vehicleId", "vehicle-123");

        // When
        String masked = PiiMasker.maskAndSerialize(map);

        // Then - VIN partially masked (show last 4 chars: 1234)
        assertThat(masked).contains("1234");
        assertThat(masked).contains("******");
        assertThat(masked).contains("vehicle-123");
        assertThat(masked).doesNotContain("ABC12345678901234");
    }

    @Test
    void maskAndSerializeShouldMaskSecurityCredentials() {
        // Given
        Map<String, Object> map = new HashMap<>();
        map.put("apiKey", "sk-123456789");
        map.put("secret", "top-secret-value");
        map.put("privateKey", "-----BEGIN PRIVATE KEY-----");
        map.put("userId", "user-456");

        // When
        String masked = PiiMasker.maskAndSerialize(map);

        // Then
        assertThat(masked).contains(MASKED);
        assertThat(masked).contains("user-456");
        assertThat(masked).doesNotContain("sk-123456789");
        assertThat(masked).doesNotContain("top-secret-value");
        assertThat(masked).doesNotContain("BEGIN PRIVATE KEY");
    }

    @Test
    void maskAndSerializeShouldPreserveNonPiiFields() {
        // Given
        Map<String, Object> map = new HashMap<>();
        map.put("clientId", "web-app");
        map.put("tenantId", "tenant-xyz");
        map.put("grantType", "authorization_code");
        map.put("scopes", "read write");

        // When
        String masked = PiiMasker.maskAndSerialize(map);

        // Then
        assertThat(masked).doesNotContain(MASKED);
        assertThat(masked).contains("web-app");
        assertThat(masked).contains("tenant-xyz");
        assertThat(masked).contains("authorization_code");
    }

    @Test
    void maskAndSerializeShouldFullyMaskShortValues() {
        // Given - values with 4 or fewer characters should be fully masked
        Map<String, Object> map = new HashMap<>();
        map.put("username", "bob");  // 3 chars - too short for partial masking
        map.put("email", "a@b.c");   // 5 chars - shows first chars + domain
        map.put("userId", "999");

        // When
        String masked = PiiMasker.maskAndSerialize(map);

        // Then
        assertThat(masked).contains(MASKED); // bob is fully masked
        assertThat(masked).contains("***MASKED***@b.c"); // email local part too short, fully masked
        assertThat(masked).contains("999");
        assertThat(masked).doesNotContain("\"bob\"");
    }

    @Test
    void maskAndSerializeShouldDifferentiateFullVsPartialMask() {
        // Given - security credentials fully masked, identification fields partially masked
        Map<String, Object> map = new HashMap<>();
        map.put("password", "mypassword123");     // Security credential - full mask
        map.put("accessToken", "bearer-token");    // Security credential - full mask
        map.put("username", "johndoe");            // Identification - partial mask
        map.put("vin", "ABC123456789012345");      // Identification - partial mask
        map.put("userId", "user-789");

        // When
        String masked = PiiMasker.maskAndSerialize(map);

        // Then
        assertThat(masked).contains(MASKED);       // password and token fully masked
        assertThat(masked).contains("jo***oe");    // username shows first 2 + last 2
        assertThat(masked).contains("******2345"); // VIN shows last 4
        assertThat(masked).contains("user-789");
        assertThat(masked).doesNotContain("mypassword123");
        assertThat(masked).doesNotContain("bearer-token");
        assertThat(masked).doesNotContain("johndoe");
        assertThat(masked).doesNotContain("ABC123456789012345");
    }
}
