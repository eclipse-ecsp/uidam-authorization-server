/*******************************************************************************
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

package org.eclipse.ecsp.oauth2.server.core.exception;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for UidamApplicationException.
 */
class UidamApplicationExceptionTest {

    @Test
    void constructor_keyStatusValues_setsAllFields() {
        UidamApplicationException ex = new UidamApplicationException("ERR_KEY", HttpStatus.BAD_REQUEST,
                "param1", "param2");

        assertEquals("ERR_KEY", ex.getKey());
        assertEquals(HttpStatus.BAD_REQUEST, ex.getHttpStatus());
        assertArrayEquals(new String[]{"param1", "param2"}, ex.getParameters());
        assertNotNull(ex.getMessage());
        assertTrue(ex.getMessage().contains("ERR_KEY"));
    }

    @Test
    void constructor_keyAndCause_setsKeyAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        UidamApplicationException ex = new UidamApplicationException("SOME_ERROR", cause);

        assertEquals("SOME_ERROR", ex.getKey());
        assertNull(ex.getHttpStatus());
        assertNull(ex.getParameters());
        assertSame(cause, ex.getCause());
    }

    @Test
    void constructor_keyAndValues_noStatus() {
        UidamApplicationException ex = new UidamApplicationException("VALIDATION_ERROR", "fieldA", "fieldB");

        assertEquals("VALIDATION_ERROR", ex.getKey());
        assertNull(ex.getHttpStatus());
        assertArrayEquals(new String[]{"fieldA", "fieldB"}, ex.getParameters());
    }

    @Test
    void constructor_noValues_emptyParameters() {
        UidamApplicationException ex = new UidamApplicationException("SIMPLE_KEY", HttpStatus.INTERNAL_SERVER_ERROR);

        assertEquals("SIMPLE_KEY", ex.getKey());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, ex.getHttpStatus());
        assertArrayEquals(new String[]{}, ex.getParameters());
    }

    @Test
    void equals_sameFields_returnsTrue() {
        UidamApplicationException ex1 = new UidamApplicationException("KEY", HttpStatus.NOT_FOUND, "p1");
        UidamApplicationException ex2 = new UidamApplicationException("KEY", HttpStatus.NOT_FOUND, "p1");

        assertEquals(ex1, ex2);
    }

    @Test
    void equals_sameInstance_returnsTrue() {
        UidamApplicationException ex = new UidamApplicationException("KEY", HttpStatus.OK);
        assertEquals(ex, ex);
    }

    @Test
    void equals_nullObject_returnsFalse() {
        UidamApplicationException ex = new UidamApplicationException("KEY", HttpStatus.OK);
        assertNotEquals(ex, null);
    }

    @Test
    void equals_differentClass_returnsFalse() {
        UidamApplicationException ex = new UidamApplicationException("KEY", HttpStatus.OK);
        assertNotEquals(ex, "string");
    }

    @Test
    void equals_differentKey_returnsFalse() {
        UidamApplicationException ex1 = new UidamApplicationException("KEY1", HttpStatus.OK);
        UidamApplicationException ex2 = new UidamApplicationException("KEY2", HttpStatus.OK);
        assertNotEquals(ex1, ex2);
    }

    @Test
    void equals_differentStatus_returnsFalse() {
        UidamApplicationException ex1 = new UidamApplicationException("KEY", HttpStatus.OK);
        UidamApplicationException ex2 = new UidamApplicationException("KEY", HttpStatus.BAD_REQUEST);
        assertNotEquals(ex1, ex2);
    }

    @Test
    void hashCode_equalObjects_sameHashCode() {
        UidamApplicationException ex1 = new UidamApplicationException("KEY", HttpStatus.NOT_FOUND, "p1");
        UidamApplicationException ex2 = new UidamApplicationException("KEY", HttpStatus.NOT_FOUND, "p1");
        assertEquals(ex1.hashCode(), ex2.hashCode());
    }

    @Test
    void hashCode_differentObjects_differentHashCodes() {
        UidamApplicationException ex1 = new UidamApplicationException("KEY1", HttpStatus.OK);
        UidamApplicationException ex2 = new UidamApplicationException("KEY2", HttpStatus.BAD_REQUEST);
        assertNotEquals(ex1.hashCode(), ex2.hashCode());
    }

    @Test
    void getMessage_containsKeyAndParameters() {
        UidamApplicationException ex = new UidamApplicationException("MY_ERROR", HttpStatus.OK,
                "val1", "val2");
        String message = ex.getMessage();
        assertNotNull(message);
        assertTrue(message.contains("MY_ERROR"));
        assertTrue(message.contains("val1") || message.contains("parameters"));
    }

    @Test
    void constructor_keyValues_messageContainsKey() {
        UidamApplicationException ex = new UidamApplicationException("SIMPLE", "a", "b");
        assertNotNull(ex.getMessage());
        assertTrue(ex.getMessage().contains("SIMPLE"));
    }
}
