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

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * The PasswordUtils class is a utility class that provides methods for password encryption.
 */
public class PasswordUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(PasswordUtils.class);

    private static final List<String> SUPPORTED_ALGORITHMS = Arrays.asList("SHA-256", "SHA-384", "SHA-512");
    public static final Map<String, Integer> UIDAM_BCRYPT_STRENGTH_MAP = Map.of("low", 4, "medium", 7, "high", 10);

    protected PasswordUtils() {
        // Prevent instantiation
    }

    /**
     * This method generates a secure password by encoding the input password using the specified encoder and salt.
     * It first creates a MessageDigest instance with the specified encoder.
     * If the salt is not empty, it is appended to the input password.
     * The input string is then converted to bytes and digested using the MessageDigest instance.
     * The digested bytes are then encoded using Base64 encoding and returned as the secure password.
     * If the specified encoder is not supported, it throws an OAuth2AuthenticationException with a server error code.
     *
     * @param password the password to be encoded.
     * @param encoder the encoder algorithm to be used.
     * @param salt the salt to be used for encoding the password.
     * @return the encoded password.
     * @throws OAuth2AuthenticationException if the specified encoder is not supported.
     */
    public static String getSecurePassword(String password, String encoder, String salt) {
        if (encoder == null || !SUPPORTED_ALGORITHMS.contains(encoder)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Unsupported or null encoder algorithm", null));
        }
        String generatedPassword;
        try {
            MessageDigest md = MessageDigest.getInstance(encoder);
            String input = password;
            if (StringUtils.isNotEmpty(salt)) {
                input = input + salt;
            }
            byte[] bytes = md.digest(input.getBytes());
            generatedPassword = Base64.getEncoder().encodeToString(bytes);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("getSecurePassword - {}", e.getMessage());
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "Unable to validate password", null);
            throw new OAuth2AuthenticationException(error);
        }
        return generatedPassword;
    }

}