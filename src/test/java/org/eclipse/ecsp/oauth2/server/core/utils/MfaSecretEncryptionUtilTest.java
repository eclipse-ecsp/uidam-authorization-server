/********************************************************************************
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
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.utils;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for {@link MfaSecretEncryptionUtil} in the authorization server.
 */
@DisplayName("MfaSecretEncryptionUtil (auth-server) Test Suite")
class MfaSecretEncryptionUtilTest {

    private static final String PLAIN_SECRET    = "JBSWY3DPEHPK3PXP";
    private static final String ENCRYPTION_KEY  = "TestEncryptionKey12345!";
    private static final String ENCRYPTION_SALT = "TestEncryptionSalt12345";

    @Test
    @DisplayName("Encrypt then decrypt round-trip should yield original secret")
    void encryptAndDecrypt_roundTrip() {
        // Use the encrypt helper (shared algorithm) then decrypt
        String encrypted = MfaSecretEncryptionUtil.encrypt(PLAIN_SECRET, ENCRYPTION_KEY, ENCRYPTION_SALT);
        assertNotNull(encrypted);
        assertNotEquals(PLAIN_SECRET, encrypted);

        String decrypted = MfaSecretEncryptionUtil.decrypt(encrypted, ENCRYPTION_KEY, ENCRYPTION_SALT);
        assertEquals(PLAIN_SECRET, decrypted);
    }

    @Test
    @DisplayName("Decrypt with wrong key should throw MfaDecryptionException")
    void decrypt_wrongKey_throws() {
        String encrypted = MfaSecretEncryptionUtil.encrypt(PLAIN_SECRET, ENCRYPTION_KEY, ENCRYPTION_SALT);
        assertThrows(MfaSecretEncryptionUtil.MfaDecryptionException.class,
                () -> MfaSecretEncryptionUtil.decrypt(encrypted, "WrongKey!!!", ENCRYPTION_SALT));
    }

    @Test
    @DisplayName("Decrypt with wrong salt should throw MfaDecryptionException")
    void decrypt_wrongSalt_throws() {
        String encrypted = MfaSecretEncryptionUtil.encrypt(PLAIN_SECRET, ENCRYPTION_KEY, ENCRYPTION_SALT);
        assertThrows(MfaSecretEncryptionUtil.MfaDecryptionException.class,
                () -> MfaSecretEncryptionUtil.decrypt(encrypted, ENCRYPTION_KEY, "WrongSalt!!!"));
    }

    @Test
    @DisplayName("Decrypt null returns null")
    void decrypt_null_returnsNull() {
        assertNull(MfaSecretEncryptionUtil.decrypt(null, ENCRYPTION_KEY, ENCRYPTION_SALT));
    }

    @Test
    @DisplayName("Decrypt empty string returns empty string")
    void decrypt_emptyString_returnsEmpty() {
        assertEquals("", MfaSecretEncryptionUtil.decrypt("", ENCRYPTION_KEY, ENCRYPTION_SALT));
    }

    @Test
    @DisplayName("Decrypt corrupted ciphertext throws MfaDecryptionException")
    void decrypt_corrupted_throwsException() {
        assertThrows(MfaSecretEncryptionUtil.MfaDecryptionException.class,
                () -> MfaSecretEncryptionUtil.decrypt("corrupted-not-base64!!!!", ENCRYPTION_KEY, ENCRYPTION_SALT));
    }

    @Test
    @DisplayName("Two encryptions of the same secret differ (random IV)")
    void encrypt_differentOutputEachTime() {
        String enc1 = MfaSecretEncryptionUtil.encrypt(PLAIN_SECRET, ENCRYPTION_KEY, ENCRYPTION_SALT);
        String enc2 = MfaSecretEncryptionUtil.encrypt(PLAIN_SECRET, ENCRYPTION_KEY, ENCRYPTION_SALT);
        assertNotEquals(enc1, enc2);
    }
}
