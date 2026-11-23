/********************************************************************************
 * Copyright (c) 2026 Harman International
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

package org.eclipse.ecsp.oauth2.server.core.utils;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Direct unit tests for {@link RequiredExpiryValidator}, covering the three safety
 * properties called out for this fix: rejection when {@code exp} is absent, success
 * when it is present (regardless of {@code nbf}), and safe handling of the subject
 * used in the rejection log line (no control-character injection, length capping).
 */
class RequiredExpiryValidatorTest {

    private static final int OVERLONG_SUBJECT_LENGTH = 200;
    private static final int CAPPED_LENGTH_WITH_ELLIPSIS = 67;

    private final RequiredExpiryValidator validator = new RequiredExpiryValidator();

    @Test
    void validateRejectsJwtWithoutExpiry() {
        Instant now = Instant.now();
        Jwt jwt = new Jwt("token-value", now, null,
                Map.of("alg", "RS256"), Map.of("sub", "attacker"));

        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertTrue(result.hasErrors());
        assertEquals("invalid_token", result.getErrors().iterator().next().getErrorCode());
    }

    @Test
    void validateAcceptsJwtWithExpiryEvenWithoutNotBefore() {
        // nbf is intentionally not required: the framework only stamps it onto
        // access tokens, not ID tokens, and this reader serves both.
        Instant now = Instant.now();
        Jwt jwt = new Jwt("token-value", now, now.plusSeconds(60),
                Map.of("alg", "RS256"), Map.of("sub", "test-user"));

        OAuth2TokenValidatorResult result = validator.validate(jwt);

        assertFalse(result.hasErrors());
    }

    @Test
    void validateRejectsNullJwt() {
        assertThrows(IllegalArgumentException.class, () -> validator.validate(null));
    }

    @Test
    void sanitiseForLogStripsControlCharactersToPreventLogInjection() {
        String maliciousSubject = "user\r\nINJECTED LOG LINE: admin granted";

        String sanitised = RequiredExpiryValidator.sanitiseForLog(maliciousSubject);

        assertFalse(sanitised.contains("\r"));
        assertFalse(sanitised.contains("\n"));
        assertTrue(sanitised.contains("INJECTED"));
    }

    @Test
    void sanitiseForLogCapsLength() {
        String longSubject = "a".repeat(OVERLONG_SUBJECT_LENGTH);

        String sanitised = RequiredExpiryValidator.sanitiseForLog(longSubject);

        // 64-char cap plus the "..." truncation marker.
        assertTrue(sanitised.length() <= CAPPED_LENGTH_WITH_ELLIPSIS);
        assertTrue(sanitised.endsWith("..."));
    }

    @Test
    void sanitiseForLogHandlesNullSubject() {
        assertEquals("<absent>", RequiredExpiryValidator.sanitiseForLog(null));
    }

    @Test
    void sanitiseForLogLeavesShortPlainSubjectUnchanged() {
        assertEquals("plain-user", RequiredExpiryValidator.sanitiseForLog("plain-user"));
    }
}
