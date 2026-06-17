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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for InputSanitizer covering all DANGEROUS_PATTERN regex branches.
 */
class InputSanitizerTest {

    @ParameterizedTest
    @NullAndEmptySource
    void isSafe_NullAndEmpty_ReturnsTrue(String input) {
        assertTrue(InputSanitizer.isSafe(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "John", "O'Reilly", "test@example.com",
        "Hello World", "user123", "New York"
    })
    void isSafe_CleanInput_ReturnsTrue(String input) {
        assertTrue(InputSanitizer.isSafe(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {"<div>", "<img src=x>", "<a href='#'>"})
    void isSafe_HtmlTags_ReturnsFalse(String input) {
        assertFalse(InputSanitizer.isSafe(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "<script>alert(1)</script>",
        "<SCRIPT>alert('xss')</SCRIPT>"
    })
    void isSafe_ScriptBlocks_ReturnsFalse(String input) {
        assertFalse(InputSanitizer.isSafe(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {"javascript:alert(1)", "JAVASCRIPT :void(0)"})
    void isSafe_JavascriptProtocol_ReturnsFalse(String input) {
        assertFalse(InputSanitizer.isSafe(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {"onclick=alert(1)", "onerror =x", "ONLOAD=f()"})
    void isSafe_EventHandlers_ReturnsFalse(String input) {
        assertFalse(InputSanitizer.isSafe(input));
    }

    @Test
    void isSafe_SqlComment_ReturnsFalse() {
        assertFalse(InputSanitizer.isSafe("admin--"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "; DROP TABLE users", ";ALTER TABLE x", ";delete from users",
        "; EXEC xp_cmdshell", ";TRUNCATE TABLE t", ";CREATE TABLE t"
    })
    void isSafe_SqlStatementsAfterSemicolon_ReturnsFalse(String input) {
        assertFalse(InputSanitizer.isSafe(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {"OR 1=1", "or1=1", "AND 1=1", "and2=2"})
    void isSafe_BooleanInjection_ReturnsFalse(String input) {
        assertFalse(InputSanitizer.isSafe(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "admin' OR 1=1", "'or1", "'and2", "test' OR true"
    })
    void isSafe_QuotePrefixedInjection_ReturnsFalse(String input) {
        assertFalse(InputSanitizer.isSafe(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {"UNION SELECT 1", "union all select *"})
    void isSafe_UnionSelect_ReturnsFalse(String input) {
        assertFalse(InputSanitizer.isSafe(input));
    }

    @Test
    void isSafe_SqlBlockComment_ReturnsFalse() {
        assertFalse(InputSanitizer.isSafe("admin/* comment */"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"&#60;", "&#60", "&#97;"})
    void isSafe_HtmlNumericEntities_ReturnsFalse(String input) {
        assertFalse(InputSanitizer.isSafe(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {"&#x3C;", "&#x3c", "&#xAB;"})
    void isSafe_HtmlHexEntities_ReturnsFalse(String input) {
        assertFalse(InputSanitizer.isSafe(input));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\\x3C", "\\x0A"})
    void isSafe_HexEscapeSequences_ReturnsFalse(String input) {
        assertFalse(InputSanitizer.isSafe(input));
    }

    @Test
    void isSafe_CaseInsensitive_ReturnsFalse() {
        assertFalse(InputSanitizer.isSafe("Javascript:void(0)"));
        assertFalse(InputSanitizer.isSafe("Union Select 1"));
        assertFalse(InputSanitizer.isSafe("Or 1=1"));
    }
}
