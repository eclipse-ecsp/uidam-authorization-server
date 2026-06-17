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

import java.util.regex.Pattern;

/**
 * Utility class for sanitizing and validating user input to prevent
 * injection attacks (SQL injection, XSS, script injection).
 */
public final class InputSanitizer {

    private InputSanitizer() {
    }

    /**
     * Pattern that matches dangerous characters and sequences commonly used
     * in SQL injection and XSS attacks: HTML tags, SQL keywords, script
     * fragments, comment sequences, and common boolean-based injection payloads.
     */
    private static final Pattern DANGEROUS_PATTERN = Pattern.compile(
            "<[^>]*>"                              // HTML/XML tags
            + "|<script[^>]*>.*?</script>"         // script blocks
            + "|javascript\\s*:"                   // javascript: protocol
            + "|on\\w+\\s*="                       // inline event handlers (onclick=, onerror=, etc.)
            + "|--"                                // SQL comment
            + "|;\\s*(?:DROP|ALTER|INSERT|UPDATE|DELETE|EXEC|UNION|CREATE|TRUNCATE)" // SQL statements after semicolon
            + "|\\b(?:OR|AND)\\s*\\d+\\s*=\\s*\\d+" // boolean injection: OR 1=1, or1=1, AND 1=1
            + "|'\\s*(?:OR|AND)(?:\\s|\\d)"        // quote-prefixed injection: ' OR ..., 'or1, 'and1
            + "|\\bUNION\\s+(?:ALL\\s+)?SELECT\\b" // UNION SELECT
            + "|/\\*.*?\\*/"                       // SQL block comments
            + "|&#\\d+;?"                          // HTML numeric entities
            + "|&#x[0-9a-fA-F]+;?"                 // HTML hex entities
            + "|\\\\x[0-9a-fA-F]{2}",              // hex escape sequences
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    /**
     * Checks whether the input contains potentially dangerous content.
     *
     * @param input the string to check
     * @return true if the input is safe (no dangerous patterns found), false otherwise
     */
    public static boolean isSafe(String input) {
        if (input == null || input.isEmpty()) {
            return true;
        }
        return !DANGEROUS_PATTERN.matcher(input).find();
    }
}
