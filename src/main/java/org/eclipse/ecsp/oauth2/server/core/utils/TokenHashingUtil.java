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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility class for consistent token hashing across all components.
 * This ensures that tokens hashed for storage and tokens hashed for lookup/validation
 * use identical algorithms, salts, and formatting.
 * 
 * <p>All token hashing operations MUST use this utility to guarantee consistency.
 *
 * @since 1.0
 */
public final class TokenHashingUtil {

    private static final String DEFAULT_HASH_ALGORITHM = "SHA-256";

    private TokenHashingUtil() {
        // Utility class - prevent instantiation
    }

    /**
     * Hashes a token using the configured algorithm and salt.
     * 
     * <p>The hash format is: {@code algorithm:base64EncodedHash}
     *
     * @param token the token to hash (must not be null)
     * @param hashAlgorithm the hash algorithm to use (e.g., "SHA-256"). If null or empty, defaults to SHA-256.
     * @param salt the salt to append to the token before hashing. If null, defaults to empty string.
     * @return the hashed token in format "algorithm:base64Hash"
     * @throws IllegalStateException if the hash algorithm is not available
     * @throws NullPointerException if token is null
     */
    public static String hashToken(String token, String hashAlgorithm, String salt) {
        if (token == null) {
            throw new NullPointerException("Token must not be null");
        }

        try {
            // Normalize inputs
            String algorithm = (hashAlgorithm == null || hashAlgorithm.isEmpty()) 
                    ? DEFAULT_HASH_ALGORITHM : hashAlgorithm;
            String effectiveSalt = salt != null ? salt : "";
            
            // Hash token with salt
            String saltedToken = token + effectiveSalt;
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hash = digest.digest(saltedToken.getBytes(StandardCharsets.UTF_8));
            
            // Return in standard format: algorithm:base64Hash
            return algorithm + ":" + Base64.getEncoder().encodeToString(hash);
            
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Hash algorithm not available: " + hashAlgorithm, e);
        }
    }

    /**
     * Gets the default hash algorithm used when none is specified.
     *
     * @return the default hash algorithm name
     */
    public static String getDefaultHashAlgorithm() {
        return DEFAULT_HASH_ALGORITHM;
    }
}
