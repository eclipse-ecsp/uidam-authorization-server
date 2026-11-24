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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Rejects JWTs that do not carry an expiry claim.
 */
public final class RequiredExpiryValidator implements OAuth2TokenValidator<Jwt> {

    private static final Logger LOGGER = LoggerFactory.getLogger(RequiredExpiryValidator.class);
    private static final String BEARER_TOKEN_ERROR_URI =
            "https://datatracker.ietf.org/doc/html/rfc6750#section-3.1";
    private static final int MAX_LOGGED_SUBJECT = 64;
    private static final long WARN_THROTTLE_MS = 60_000L;
    private static final AtomicLong LAST_WARN_AT_MS = new AtomicLong(0L);

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        Assert.notNull(jwt, "jwt cannot be null");
        if (jwt.getExpiresAt() != null) {
            return OAuth2TokenValidatorResult.success();
        }

        logMissingExpiry(jwt.getSubject());
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_TOKEN,
                "The token carries no exp claim",
                BEARER_TOKEN_ERROR_URI));
    }

    /**
     * Logs a missing-expiry rejection without recording token contents.
     *
     * @param subject token subject to sanitize before logging
     */
    public static void logMissingExpiry(String subject) {
        long nowMs = System.currentTimeMillis();
        long lastMs = LAST_WARN_AT_MS.get();
        if (nowMs - lastMs >= WARN_THROTTLE_MS && LAST_WARN_AT_MS.compareAndSet(lastMs, nowMs)) {
            LOGGER.warn("Rejecting JWT without exp claim; sub={}", sanitiseForLog(subject));
        }
    }

    static String sanitiseForLog(String value) {
        if (value == null) {
            return "<absent>";
        }
        StringBuilder cleaned = new StringBuilder(Math.min(value.length(), MAX_LOGGED_SUBJECT));
        for (int i = 0; i < value.length() && cleaned.length() < MAX_LOGGED_SUBJECT; i++) {
            char character = value.charAt(i);
            cleaned.append(Character.isISOControl(character) ? '_' : character);
        }
        if (value.length() > MAX_LOGGED_SUBJECT) {
            cleaned.append("...");
        }
        return cleaned.toString();
    }
}
