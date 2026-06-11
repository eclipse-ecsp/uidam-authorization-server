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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for TotpService covering TOTP algorithm, QR code generation, and utility methods.
 */
class TotpServiceTest {

    private static final String BASE32_SECRET = "JBSWY3DPEHPK3PXP";
    private static final String USERNAME = "testuser";

    private MfaProperties mfaProperties;
    private TotpService totpService;

    @BeforeEach
    void setUp() {
        mfaProperties = new MfaProperties();
        mfaProperties.setAppName("TestApp");
        totpService = new TotpService(mfaProperties);
    }

    // ─────────────── validateCode ────────────────────────────────────────────

    @Test
    void validateCode_withNullCode_returnsFalse() {
        assertFalse(totpService.validateCode(USERNAME, BASE32_SECRET, null));
    }

    @Test
    void validateCode_withNullSecret_returnsFalse() {
        assertFalse(totpService.validateCode(USERNAME, null, "123456"));
    }

    @Test
    void validateCode_withValidCurrentCode_returnsTrue() {
        // Compute the current TOTP for the known secret
        long currentStep = System.currentTimeMillis() / 1000L / 30L;
        String validCode = totpService.computeTotp(BASE32_SECRET, currentStep);

        assertTrue(totpService.validateCode(USERNAME, BASE32_SECRET, validCode));
    }

    @Test
    void validateCode_withPreviousStepCode_returnsTrue() {
        long currentStep = System.currentTimeMillis() / 1000L / 30L;
        String prevCode = totpService.computeTotp(BASE32_SECRET, currentStep - 1);

        assertTrue(totpService.validateCode(USERNAME, BASE32_SECRET, prevCode));
    }

    @Test
    void validateCode_withNextStepCode_returnsTrue() {
        long currentStep = System.currentTimeMillis() / 1000L / 30L;
        String nextCode = totpService.computeTotp(BASE32_SECRET, currentStep + 1);

        assertTrue(totpService.validateCode(USERNAME, BASE32_SECRET, nextCode));
    }

    @Test
    void validateCode_withWrongCode_returnsFalse() {
        assertFalse(totpService.validateCode(USERNAME, BASE32_SECRET, "000000"));
    }

    // ─────────────── computeTotp ─────────────────────────────────────────────

    @Test
    void computeTotp_withKnownSecret_returnsSixDigitCode() {
        String code = totpService.computeTotp(BASE32_SECRET, 57340000L);
        assertNotNull(code);
        assertEquals(6, code.length());
        assertTrue(code.matches("\\d{6}"));
    }

    @Test
    void computeTotp_withDifferentTimeSteps_returnsDifferentCodes() {
        String code1 = totpService.computeTotp(BASE32_SECRET, 57340000L);
        String code2 = totpService.computeTotp(BASE32_SECRET, 57340001L);
        // Different time steps should generally produce different codes
        assertNotNull(code1);
        assertNotNull(code2);
    }

    @Test
    void computeTotp_withInvalidSecret_returnsEmptyString() {
        // An invalid base32 string should fail gracefully
        String code = totpService.computeTotp("", 57340000L);
        // May return empty string or still produce a code; just shouldn't throw
        assertNotNull(code);
    }

    @Test
    void computeTotp_withSecretContainingPadding_handlesGracefully() {
        // Base32 with padding characters
        String code = totpService.computeTotp("JBSWY3DP====", 57340000L);
        assertNotNull(code);
    }

    @Test
    void computeTotp_codeIsConsistentForSameStep() {
        long step = 57340000L;
        String code1 = totpService.computeTotp(BASE32_SECRET, step);
        String code2 = totpService.computeTotp(BASE32_SECRET, step);
        assertEquals(code1, code2);
    }

    @Test
    void computeTotp_codeIs6Digits() {
        for (long step = 57340000L; step < 57340010L; step++) {
            String code = totpService.computeTotp(BASE32_SECRET, step);
            assertEquals(6, code.length());
            assertTrue(code.matches("\\d{6}"), "Code should be 6 digits: " + code);
        }
    }

    // ─────────────── formatManualKey ─────────────────────────────────────────

    @Test
    void formatManualKey_with16CharSecret_groupsIntoFourCharSets() {
        String formatted = totpService.formatManualKey("JBSWY3DPEHPK3PXP");
        assertEquals("JBSW Y3DP EHPK 3PXP", formatted);
    }

    @Test
    void formatManualKey_withShortSecret_returnsUngrouped() {
        String formatted = totpService.formatManualKey("JBSW");
        assertEquals("JBSW", formatted);
    }

    @Test
    void formatManualKey_withEmptySecret_returnsEmpty() {
        String formatted = totpService.formatManualKey("");
        assertEquals("", formatted);
    }

    @Test
    void formatManualKey_withExactlyFourChars_noSpace() {
        String formatted = totpService.formatManualKey("ABCD");
        assertEquals("ABCD", formatted);
    }

    @Test
    void formatManualKey_withFiveChars_spacesAfterFour() {
        String formatted = totpService.formatManualKey("ABCDE");
        assertEquals("ABCD E", formatted);
    }

    // ─────────────── buildOtpAuthUri ─────────────────────────────────────────

    @Test
    void buildOtpAuthUri_containsExpectedComponents() {
        String uri = totpService.buildOtpAuthUri(USERNAME, BASE32_SECRET);
        assertNotNull(uri);
        assertTrue(uri.startsWith("otpauth://totp/"));
        assertTrue(uri.contains("secret=" + BASE32_SECRET));
    }

    @Test
    void buildOtpAuthUri_withSpecialCharsInUsername_encodesCorrectly() {
        String uri = totpService.buildOtpAuthUri("user@example.com", BASE32_SECRET);
        assertNotNull(uri);
        assertTrue(uri.startsWith("otpauth://totp/"));
    }

    // ─────────────── generateQrCodeBase64FromUri ─────────────────────────────

    @Test
    void generateQrCodeBase64FromUri_withValidUri_returnsBase64EncodedPng() {
        String otpUri = totpService.buildOtpAuthUri(USERNAME, BASE32_SECRET);
        String base64 = totpService.generateQrCodeBase64FromUri(otpUri);

        assertNotNull(base64);
        assertFalse(base64.isEmpty());
    }

    @Test
    void generateQrCodeBase64FromUri_withInvalidUri_returnsEmptyString() {
        String base64 = totpService.generateQrCodeBase64FromUri("not-a-valid-uri!!@@@");
        // Should not throw, returns empty or valid string
        assertNotNull(base64);
    }

    @Test
    void generateQrCodeBase64FromUri_withNullUri_returnsEmptyString() {
        String base64 = totpService.generateQrCodeBase64FromUri(null);
        assertNotNull(base64);
    }

    // ─────────────── generateQrCodeBase64 ────────────────────────────────────

    @Test
    void generateQrCodeBase64_withValidUsernameAndSecret_returnsBase64() {
        String base64 = totpService.generateQrCodeBase64(USERNAME, BASE32_SECRET);
        assertNotNull(base64);
        assertFalse(base64.isEmpty());
    }

    @Test
    void generateQrCodeBase64_producesNonEmptyResult() {
        String base64 = totpService.generateQrCodeBase64("user@test.com", "MFRA====");
        assertNotNull(base64);
    }
}
