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

package org.eclipse.ecsp.oauth2.server.core.response;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for ResponseMessage covering constructors, getters/setters, equals, hashCode, toString.
 */
class ResponseMessageTest {

    @Test
    void noArgsConstructor_createsEmptyMessage() {
        ResponseMessage msg = new ResponseMessage();
        assertNotNull(msg);
        assertNotNull(msg.getParameters());
        assertTrue(msg.getParameters().isEmpty());
    }

    @Test
    void constructor_withKey_setsKey() {
        ResponseMessage msg = new ResponseMessage("MY_KEY");
        assertEquals("MY_KEY", msg.getKey());
        assertNotNull(msg.getParameters());
        assertTrue(msg.getParameters().isEmpty());
    }

    @Test
    void constructor_withKeyAndVarargs_setsKeyAndParameters() {
        ResponseMessage msg = new ResponseMessage("KEY", "param1", "param2");
        assertEquals("KEY", msg.getKey());
        assertEquals(2, msg.getParameters().size());
        assertTrue(msg.getParameters().contains("param1"));
        assertTrue(msg.getParameters().contains("param2"));
    }

    @Test
    void constructor_withKeyAndList_setsKeyAndParameters() {
        List<Object> params = new ArrayList<>();
        params.add("p1");
        params.add(42);
        ResponseMessage msg = new ResponseMessage("LIST_KEY", params);
        assertEquals("LIST_KEY", msg.getKey());
        assertEquals(2, msg.getParameters().size());
    }

    @Test
    void setKey_updatesKey() {
        ResponseMessage msg = new ResponseMessage();
        msg.setKey("NEW_KEY");
        assertEquals("NEW_KEY", msg.getKey());
    }

    @Test
    void setParameters_updatesParameters() {
        ResponseMessage msg = new ResponseMessage("KEY");
        List<Object> newParams = new ArrayList<>();
        newParams.add("updated");
        msg.setParameters(newParams);
        assertEquals(1, msg.getParameters().size());
        assertEquals("updated", msg.getParameters().get(0));
    }

    @Test
    void equals_sameKeyAndParameters_returnsTrue() {
        ResponseMessage msg1 = new ResponseMessage("KEY", "param");
        ResponseMessage msg2 = new ResponseMessage("KEY", "param");
        assertEquals(msg1, msg2);
    }

    @Test
    void equals_sameInstance_returnsTrue() {
        ResponseMessage msg = new ResponseMessage("KEY");
        assertEquals(msg, msg);
    }

    @Test
    void equals_null_returnsFalse() {
        ResponseMessage msg = new ResponseMessage("KEY");
        assertNotEquals(null, msg);
    }

    @Test
    void equals_differentClass_returnsFalse() {
        ResponseMessage msg = new ResponseMessage("KEY");
        assertNotEquals("some string", msg);
    }

    @Test
    void equals_differentKey_returnsFalse() {
        ResponseMessage msg1 = new ResponseMessage("KEY1");
        ResponseMessage msg2 = new ResponseMessage("KEY2");
        assertNotEquals(msg1, msg2);
    }

    @Test
    void hashCode_equalObjects_sameHashCode() {
        ResponseMessage msg1 = new ResponseMessage("KEY", "param");
        ResponseMessage msg2 = new ResponseMessage("KEY", "param");
        assertEquals(msg1.hashCode(), msg2.hashCode());
    }

    @Test
    void toString_containsKeyAndParameters() {
        ResponseMessage msg = new ResponseMessage("MY_KEY", "p1", "p2");
        String str = msg.toString();
        assertNotNull(str);
        assertTrue(str.contains("MY_KEY"));
        assertTrue(str.contains("parameters"));
    }
}
