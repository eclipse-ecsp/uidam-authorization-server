/*
 *
 *   ******************************************************************************
 *
 *    Copyright (c) 2023-24 Harman International
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *
 *    you may not use this file except in compliance with the License.
 *
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *    See the License for the specific language governing permissions and
 *
 *    limitations under the License.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    *******************************************************************************
 *
 */

package org.eclipse.ecsp.uidam.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for DatabaseNameValidationMode enum.
 */
class DatabaseNameValidationModeTest {

    @Test
    void testFromString_None() {
        assertEquals(DatabaseNameValidationMode.NONE, 
                    DatabaseNameValidationMode.fromString("NONE"));
        assertEquals(DatabaseNameValidationMode.NONE, 
                    DatabaseNameValidationMode.fromString("none"));
        assertEquals(DatabaseNameValidationMode.NONE, 
                    DatabaseNameValidationMode.fromString("None"));
    }

    @Test
    void testFromString_Equal() {
        assertEquals(DatabaseNameValidationMode.EQUAL, 
                    DatabaseNameValidationMode.fromString("EQUAL"));
        assertEquals(DatabaseNameValidationMode.EQUAL, 
                    DatabaseNameValidationMode.fromString("equal"));
        assertEquals(DatabaseNameValidationMode.EQUAL, 
                    DatabaseNameValidationMode.fromString("Equal"));
    }

    @Test
    void testFromString_Prefix() {
        assertEquals(DatabaseNameValidationMode.PREFIX, 
                    DatabaseNameValidationMode.fromString("PREFIX"));
        assertEquals(DatabaseNameValidationMode.PREFIX, 
                    DatabaseNameValidationMode.fromString("prefix"));
        assertEquals(DatabaseNameValidationMode.PREFIX, 
                    DatabaseNameValidationMode.fromString("Prefix"));
    }

    @Test
    void testFromString_Contains() {
        assertEquals(DatabaseNameValidationMode.CONTAINS, 
                    DatabaseNameValidationMode.fromString("CONTAINS"));
        assertEquals(DatabaseNameValidationMode.CONTAINS, 
                    DatabaseNameValidationMode.fromString("contains"));
        assertEquals(DatabaseNameValidationMode.CONTAINS, 
                    DatabaseNameValidationMode.fromString("Contains"));
    }

    @Test
    void testFromString_Null_ReturnsDefault() {
        assertEquals(DatabaseNameValidationMode.EQUAL, 
                    DatabaseNameValidationMode.fromString(null));
    }

    @Test
    void testFromString_Empty_ReturnsDefault() {
        assertEquals(DatabaseNameValidationMode.EQUAL, 
                    DatabaseNameValidationMode.fromString(""));
        assertEquals(DatabaseNameValidationMode.EQUAL, 
                    DatabaseNameValidationMode.fromString("   "));
    }

    @Test
    void testFromString_Invalid_ReturnsDefault() {
        assertEquals(DatabaseNameValidationMode.EQUAL, 
                    DatabaseNameValidationMode.fromString("INVALID"));
        assertEquals(DatabaseNameValidationMode.EQUAL, 
                    DatabaseNameValidationMode.fromString("xyz"));
    }

    @Test
    void testFromString_WithWhitespace() {
        assertEquals(DatabaseNameValidationMode.PREFIX, 
                    DatabaseNameValidationMode.fromString("  PREFIX  "));
        assertEquals(DatabaseNameValidationMode.CONTAINS, 
                    DatabaseNameValidationMode.fromString(" CONTAINS "));
    }
}
