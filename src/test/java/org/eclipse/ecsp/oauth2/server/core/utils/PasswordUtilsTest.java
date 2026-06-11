/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.utils;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_ENCODER;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_SALT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

/**
 * This class tests the functionality of the PasswordUtils class.
 */
class PasswordUtilsTest {

    /**
     * This test method tests the getSecurePassword method of the PasswordUtils class with a valid password, encoder,
     * and salt.
     * It asserts that the returned string is not null and matches the expected encrypted password.
     */
    @Test
    void testGetSecurePasswordSuccess() {
        assertNotNull(PasswordUtils.getSecurePassword(TEST_PASSWORD, TEST_ENCODER, TEST_SALT));
        assertEquals("43DnFsXBdlZfdw0zJe2iCTthbC03v/lhoNrvwZtJtW4=",
            PasswordUtils.getSecurePassword(TEST_PASSWORD, TEST_ENCODER, TEST_SALT));
    }

    /**
     * This test method tests the getSecurePassword method of the PasswordUtils class with a valid password, encoder,
     * and an empty salt.
     * It asserts that the returned string is not null and matches the expected encrypted password.
     */
    @Test
    void testGetSecurePasswordSaltEmpty() {
        assertNotNull(PasswordUtils.getSecurePassword(TEST_PASSWORD, TEST_ENCODER, ""));
        assertEquals("8kiTENvnwhY8jPnlzzEW9yKoHVSiw1WC+n++PMIBhBE=",
            PasswordUtils.getSecurePassword(TEST_PASSWORD, TEST_ENCODER, ""));
    }

    /**
     * This test method tests the getSecurePassword method of the PasswordUtils class with a valid password, encoder,
     * and a null salt.
     * It asserts that the returned string is not null and matches the expected encrypted password.
     */
    @Test
    void testGetSecurePasswordSaltNull() {
        assertNotNull(PasswordUtils.getSecurePassword(TEST_PASSWORD, TEST_ENCODER, null));
        assertEquals("8kiTENvnwhY8jPnlzzEW9yKoHVSiw1WC+n++PMIBhBE=",
            PasswordUtils.getSecurePassword(TEST_PASSWORD, TEST_ENCODER, null));
    }

    /**
     * This test method tests the getSecurePassword method of the PasswordUtils class with an invalid encoder, expecting
     * an OAuth2AuthenticationException.
     * It asserts that an OAuth2AuthenticationException is thrown.
     */
    @Test
    void testGetSecurePasswordException() {
        assertThrows(OAuth2AuthenticationException.class,
                () -> PasswordUtils.getSecurePassword(TEST_PASSWORD, "SHA-255", "testSalt"));
    }

    @Test
    void getSecurePassword_noSuchAlgorithmException() {
        String password = "password123";
        String encoder = "SHA-999"; // Invalid algorithm
        String salt = "";

        assertThrows(OAuth2AuthenticationException.class, () ->
                PasswordUtils.getSecurePassword(password, encoder, salt));
    }

    /**
     * This test method covers the catch block for NoSuchAlgorithmException in getSecurePassword.
     * It mocks MessageDigest.getInstance() to throw NoSuchAlgorithmException even for a valid
     * supported algorithm, verifying that an OAuth2AuthenticationException with SERVER_ERROR is thrown.
     */
    @Test
    void testGetSecurePasswordCatchNoSuchAlgorithmException() {
        try (MockedStatic<MessageDigest> mockedMessageDigest = mockStatic(MessageDigest.class)) {
            mockedMessageDigest.when(() -> MessageDigest.getInstance(anyString()))
                    .thenThrow(new NoSuchAlgorithmException("Algorithm not found"));

            OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                    () -> PasswordUtils.getSecurePassword(TEST_PASSWORD, TEST_ENCODER, TEST_SALT));

            assertEquals(OAuth2ErrorCodes.SERVER_ERROR, exception.getError().getErrorCode());
        }
    }

}