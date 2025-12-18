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

package org.eclipse.ecsp.oauth2.server.core.response;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for BaseRepresentation.
 */
class BaseRepresentationTest {

    private static final int EXPECTED_SIZE_TWO = 2;
    private static final int EXPECTED_SIZE_THREE = 3;

    @Test
    void testNoArgsConstructor() {
        BaseRepresentation representation = new BaseRepresentation();
        
        assertThat(representation).isNotNull();
        assertThat(representation.getMessages()).isNotNull();
        assertThat(representation.getMessages()).isEmpty();
    }

    @Test
    void testConstructorWithMessages() {
        List<ResponseMessage> messages = new ArrayList<>();
        ResponseMessage message = new ResponseMessage();
        messages.add(message);
        
        BaseRepresentation representation = new BaseRepresentation(messages);
        
        assertThat(representation.getMessages()).isNotNull();
        assertThat(representation.getMessages()).hasSize(1);
        assertThat(representation.getMessages()).containsExactly(message);
    }

    @Test
    void testGetMessagesInitializesEmptyList() {
        BaseRepresentation representation = new BaseRepresentation();
        
        List<ResponseMessage> messages = representation.getMessages();
        
        assertThat(messages).isNotNull();
        assertThat(messages).isEmpty();
    }

    @Test
    void testSetMessages() {
        BaseRepresentation representation = new BaseRepresentation();
        List<ResponseMessage> messages = new ArrayList<>();
        ResponseMessage message1 = new ResponseMessage();
        ResponseMessage message2 = new ResponseMessage();
        messages.add(message1);
        messages.add(message2);
        
        representation.setMessages(messages);
        
        assertThat(representation.getMessages()).hasSize(EXPECTED_SIZE_TWO);
        assertThat(representation.getMessages()).containsExactly(message1, message2);
    }

    @Test
    void testAddMessage() {
        BaseRepresentation representation = new BaseRepresentation();
        ResponseMessage message = new ResponseMessage();
        
        representation.addMessage(message);
        
        assertThat(representation.getMessages()).hasSize(1);
        assertThat(representation.getMessages()).containsExactly(message);
    }

    @Test
    void testAddMultipleMessages() {
        BaseRepresentation representation = new BaseRepresentation();
        ResponseMessage message1 = new ResponseMessage();
        ResponseMessage message2 = new ResponseMessage();
        ResponseMessage message3 = new ResponseMessage();
        
        representation.addMessage(message1);
        representation.addMessage(message2);
        representation.addMessage(message3);
        
        assertThat(representation.getMessages()).hasSize(EXPECTED_SIZE_THREE);
        assertThat(representation.getMessages()).containsExactly(message1, message2, message3);
    }

    @Test
    void testEqualsWithSameObject() {
        BaseRepresentation representation = new BaseRepresentation();
        
        assertThat(representation.equals(representation)).isTrue();
    }

    @Test
    void testEqualsWithNull() {
        BaseRepresentation representation = new BaseRepresentation();
        
        assertThat(representation.equals(null)).isFalse();
    }

    @Test
    void testEqualsWithDifferentClass() {
        BaseRepresentation representation = new BaseRepresentation();
        String differentObject = "different";
        
        assertThat(representation.equals(differentObject)).isFalse();
    }

    @Test
    void testEqualsWithEqualObjects() {
        List<ResponseMessage> messages1 = new ArrayList<>();
        ResponseMessage message = new ResponseMessage();
        messages1.add(message);
        
        List<ResponseMessage> messages2 = new ArrayList<>();
        messages2.add(message);
        
        BaseRepresentation representation1 = new BaseRepresentation(messages1);
        BaseRepresentation representation2 = new BaseRepresentation(messages2);
        
        assertThat(representation1.equals(representation2)).isTrue();
    }

    @Test
    void testEqualsWithDifferentMessages() {
        List<ResponseMessage> messages1 = new ArrayList<>();
        messages1.add(new ResponseMessage());
        
        List<ResponseMessage> messages2 = new ArrayList<>();
        messages2.add(new ResponseMessage());
        messages2.add(new ResponseMessage());
        
        BaseRepresentation representation1 = new BaseRepresentation(messages1);
        BaseRepresentation representation2 = new BaseRepresentation(messages2);
        
        assertThat(representation1.equals(representation2)).isFalse();
    }

    @Test
    void testHashCodeConsistency() {
        List<ResponseMessage> messages = new ArrayList<>();
        ResponseMessage message = new ResponseMessage();
        messages.add(message);
        
        BaseRepresentation representation = new BaseRepresentation(messages);
        
        int hashCode1 = representation.hashCode();
        int hashCode2 = representation.hashCode();
        
        assertThat(hashCode1).isEqualTo(hashCode2);
    }

    @Test
    void testHashCodeEqualityForEqualObjects() {
        List<ResponseMessage> messages1 = new ArrayList<>();
        ResponseMessage message = new ResponseMessage();
        messages1.add(message);
        
        List<ResponseMessage> messages2 = new ArrayList<>();
        messages2.add(message);
        
        BaseRepresentation representation1 = new BaseRepresentation(messages1);
        BaseRepresentation representation2 = new BaseRepresentation(messages2);
        
        assertThat(representation1.hashCode()).isEqualTo(representation2.hashCode());
    }

    @Test
    void testToStringWithEmptyMessages() {
        BaseRepresentation representation = new BaseRepresentation();
        
        String result = representation.toString();
        
        assertThat(result).contains("BaseRepresentation");
        assertThat(result).contains("messages");
    }

    @Test
    void testToStringWithMessages() {
        List<ResponseMessage> messages = new ArrayList<>();
        messages.add(new ResponseMessage());
        
        BaseRepresentation representation = new BaseRepresentation(messages);
        
        String result = representation.toString();
        
        assertThat(result).contains("BaseRepresentation");
        assertThat(result).contains("messages");
    }

    @Test
    void testConstructorWithNullMessages() {
        BaseRepresentation representation = new BaseRepresentation(null);
        
        // getMessages() should initialize empty list when messages is null
        assertThat(representation.getMessages()).isNotNull();
        assertThat(representation.getMessages()).isEmpty();
    }
}
