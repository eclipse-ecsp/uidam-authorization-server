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

import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.util.Assert;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Calculates the token hash value used by the OpenID Connect {@code at_hash} and
 * {@code c_hash} claims.
 */
public final class OidcTokenHashingUtil {

    private static final int SHA_256_BITS = 256;
    private static final int SHA_384_BITS = 384;
    private static final int SHA_512_BITS = 512;

    private OidcTokenHashingUtil() {
    }

    /**
     * Hashes a token using the digest associated with the ID token's JWS algorithm,
     * retains the left-most half, and Base64 URL-encodes the result without padding.
     *
     * @param tokenValue access-token or authorization-code value
     * @param signingAlgorithm ID-token JWS signing algorithm
     * @return OpenID Connect token hash
     */
    public static String createTokenHash(String tokenValue, JwsAlgorithm signingAlgorithm) {
        Assert.hasText(tokenValue, "tokenValue cannot be empty");
        Assert.notNull(signingAlgorithm, "signingAlgorithm cannot be null");

        String digestAlgorithm = resolveDigestAlgorithm(signingAlgorithm.getName());
        try {
            byte[] digest = MessageDigest.getInstance(digestAlgorithm)
                    .digest(tokenValue.getBytes(StandardCharsets.US_ASCII));
            byte[] leftHalf = Arrays.copyOf(digest, digest.length / 2);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(leftHalf);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Digest algorithm is unavailable: " + digestAlgorithm, exception);
        }
    }

    private static String resolveDigestAlgorithm(String signingAlgorithm) {
        if (signingAlgorithm.endsWith(String.valueOf(SHA_256_BITS))) {
            return "SHA-256";
        }
        if (signingAlgorithm.endsWith(String.valueOf(SHA_384_BITS))) {
            return "SHA-384";
        }
        if (signingAlgorithm.endsWith(String.valueOf(SHA_512_BITS))) {
            return "SHA-512";
        }
        throw new IllegalArgumentException("Unsupported ID-token signing algorithm: " + signingAlgorithm);
    }
}
