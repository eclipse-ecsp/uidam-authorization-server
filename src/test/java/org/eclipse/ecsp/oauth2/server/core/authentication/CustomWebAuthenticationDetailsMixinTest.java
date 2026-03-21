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

package org.eclipse.ecsp.oauth2.server.core.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test class for CustomWebAuthenticationDetailsMixin.
 * This tests the Jackson mixin functionality for JSON serialization/deserialization.
 */
class CustomWebAuthenticationDetailsMixinTest {
    
    private ObjectMapper objectMapper;
    
    @BeforeEach
    void setUp() {
        objectMapper = JsonMapper.builder().build();
        // Register the mixin for CustomWebAuthenticationDetails
        objectMapper.addMixIn(CustomWebAuthenticationDetails.class, CustomWebAuthenticationDetailsMixin.class);
    }
    
    @Test
    void testSerializationWithMixin() throws Exception {
        // Arrange
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(
                "192.168.1.100",
                "session-123",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0",
                "en-US,en;q=0.9",
                "https://example.com/previous-page"
        );
        
        // Act
        String json = objectMapper.writeValueAsString(details);
        
        // Assert
        assertNotNull(json);
        assertTrue(json.contains("192.168.1.100"));
        assertTrue(json.contains("session-123"));
        assertTrue(json.contains("Chrome"));
        assertTrue(json.contains("en-US"));
        assertTrue(json.contains("example.com"));
    }
    
    @Test
    void testDeserializationWithMixin() throws Exception {
        // Arrange
        String json = "{"
                + "\"remoteAddress\":\"10.0.0.1\","
                + "\"sessionId\":\"abc-session-456\","
                + "\"userAgent\":\"Safari/14.0\","
                + "\"acceptLanguage\":\"fr-FR,fr;q=0.9\","
                + "\"referer\":\"https://test.com/path\""
                + "}";
        
        // Act
        CustomWebAuthenticationDetails details = objectMapper.readValue(json,
                CustomWebAuthenticationDetails.class);
        
        // Assert
        assertNotNull(details);
        assertEquals("10.0.0.1", details.getRemoteAddress());
        assertEquals("abc-session-456", details.getSessionId());
        assertEquals("Safari/14.0", details.getUserAgent());
        assertEquals("fr-FR,fr;q=0.9", details.getAcceptLanguage());
        assertEquals("https://test.com/path", details.getReferer());
    }
    
    @Test
    void testSerializationDeserializationRoundTrip() throws Exception {
        // Arrange
        CustomWebAuthenticationDetails original = new CustomWebAuthenticationDetails(
                "172.16.0.50",
                "test-session-xyz",
                "Firefox/95.0",
                "de-DE,de;q=0.9,en;q=0.8",
                "https://portal.example.com/dashboard"
        );
        
        // Act - Serialize
        String json = objectMapper.writeValueAsString(original);
        
        // Act - Deserialize
        CustomWebAuthenticationDetails deserialized = objectMapper.readValue(json,
                CustomWebAuthenticationDetails.class);
        
        // Assert
        assertNotNull(deserialized);
        assertEquals(original.getRemoteAddress(), deserialized.getRemoteAddress());
        assertEquals(original.getSessionId(), deserialized.getSessionId());
        assertEquals(original.getUserAgent(), deserialized.getUserAgent());
        assertEquals(original.getAcceptLanguage(), deserialized.getAcceptLanguage());
        assertEquals(original.getReferer(), deserialized.getReferer());
    }
    
    @Test
    void testDeserializationWithNullValues() throws Exception {
        // Arrange
        String json = "{"
                + "\"remoteAddress\":\"127.0.0.1\","
                + "\"sessionId\":null,"
                + "\"userAgent\":null,"
                + "\"acceptLanguage\":null,"
                + "\"referer\":null"
                + "}";
        
        // Act
        CustomWebAuthenticationDetails details = objectMapper.readValue(json,
                CustomWebAuthenticationDetails.class);
        
        // Assert
        assertNotNull(details);
        assertEquals("127.0.0.1", details.getRemoteAddress());
        assertNull(details.getSessionId());
        assertNull(details.getUserAgent());
        assertNull(details.getAcceptLanguage());
        assertNull(details.getReferer());
    }
    
    @Test
    void testDeserializationWithMissingFields() throws Exception {
        // Arrange
        String json = "{"
                + "\"remoteAddress\":\"192.168.0.1\","
                + "\"sessionId\":\"minimal-session\""
                + "}";
        
        // Act
        CustomWebAuthenticationDetails details = objectMapper.readValue(json,
                CustomWebAuthenticationDetails.class);
        
        // Assert
        assertNotNull(details);
        assertEquals("192.168.0.1", details.getRemoteAddress());
        assertEquals("minimal-session", details.getSessionId());
        // Other fields should be null as they were not in the JSON
        assertNull(details.getUserAgent());
        assertNull(details.getAcceptLanguage());
        assertNull(details.getReferer());
    }
    
    @Test
    void testSerializationWithSpecialCharacters() throws Exception {
        // Arrange
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(
                "fe80::1",  // IPv6 address
                "session-with-特殊字符",  // Special characters
                "Mozilla/5.0 (Linux; Android 11) \"Quoted\"",
                "zh-CN,zh;q=0.9",
                "https://example.com/path?param=value&other=123"
        );
        
        // Act
        String json = objectMapper.writeValueAsString(details);
        CustomWebAuthenticationDetails deserialized = objectMapper.readValue(json,
                CustomWebAuthenticationDetails.class);
        
        // Assert
        assertNotNull(deserialized);
        assertEquals(details.getRemoteAddress(), deserialized.getRemoteAddress());
        assertEquals(details.getSessionId(), deserialized.getSessionId());
        assertEquals(details.getUserAgent(), deserialized.getUserAgent());
        assertEquals(details.getAcceptLanguage(), deserialized.getAcceptLanguage());
        assertEquals(details.getReferer(), deserialized.getReferer());
    }
}
