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

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link CustomWebAuthenticationDetails}.
 *
 * @author UIDAM Team
 */
class CustomWebAuthenticationDetailsTest {

    @Test
    void testConstructorWithHttpServletRequest() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.100");
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        request.addHeader("Accept-Language", "en-US,en;q=0.9");
        request.addHeader("Referer", "https://example.com/login");
        
        HttpSession session = new MockHttpSession(null, "TEST-SESSION-123");
        request.setSession(session);

        // Act
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(request);

        // Assert
        assertEquals("192.168.1.100", details.getRemoteAddress());
        assertEquals("TEST-SESSION-123", details.getSessionId());
        assertEquals("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", details.getUserAgent());
        assertEquals("en-US,en;q=0.9", details.getAcceptLanguage());
        assertEquals("https://example.com/login", details.getReferer());
    }

    @Test
    void testConstructorWithHttpServletRequest_MissingHeaders() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");

        // Act
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(request);

        // Assert
        assertEquals("10.0.0.1", details.getRemoteAddress());
        assertNull(details.getSessionId());
        assertNull(details.getUserAgent());
        assertNull(details.getAcceptLanguage());
        assertNull(details.getReferer());
    }

    @Test
    void testConstructorWithParameters() {
        // Arrange & Act
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(
            "172.16.0.1",
            "SESSION-456",
            "Chrome/120.0",
            "fr-FR,fr;q=0.9",
            "https://example.org/home"
        );

        // Assert
        assertEquals("172.16.0.1", details.getRemoteAddress());
        assertEquals("SESSION-456", details.getSessionId());
        assertEquals("Chrome/120.0", details.getUserAgent());
        assertEquals("fr-FR,fr;q=0.9", details.getAcceptLanguage());
        assertEquals("https://example.org/home", details.getReferer());
    }

    @Test
    void testEquals_SameObject() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.100");
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(request);

        // Act & Assert
        assertEquals(details, details);
    }

    @Test
    void testEquals_EqualObjects() {
        // Arrange
        CustomWebAuthenticationDetails details1 = new CustomWebAuthenticationDetails(
            "192.168.1.100",
            "SESSION-123",
            "Mozilla/5.0",
            "en-US",
            "https://example.com"
        );

        CustomWebAuthenticationDetails details2 = new CustomWebAuthenticationDetails(
            "192.168.1.100",
            "SESSION-123",
            "Mozilla/5.0",
            "en-US",
            "https://example.com"
        );

        // Act & Assert
        assertEquals(details1, details2);
        assertEquals(details1.hashCode(), details2.hashCode());
    }

    @Test
    void testEquals_DifferentUserAgent() {
        // Arrange
        CustomWebAuthenticationDetails details1 = new CustomWebAuthenticationDetails(
            "192.168.1.100",
            "SESSION-123",
            "Mozilla/5.0",
            "en-US",
            "https://example.com"
        );

        CustomWebAuthenticationDetails details2 = new CustomWebAuthenticationDetails(
            "192.168.1.100",
            "SESSION-123",
            "Chrome/120.0",
            "en-US",
            "https://example.com"
        );

        // Act & Assert
        assertNotEquals(details1, details2);
    }

    @Test
    void testEquals_DifferentRemoteAddress() {
        // Arrange
        CustomWebAuthenticationDetails details1 = new CustomWebAuthenticationDetails(
            "192.168.1.100",
            "SESSION-123",
            "Mozilla/5.0",
            "en-US",
            "https://example.com"
        );

        CustomWebAuthenticationDetails details2 = new CustomWebAuthenticationDetails(
            "10.0.0.1",
            "SESSION-123",
            "Mozilla/5.0",
            "en-US",
            "https://example.com"
        );

        // Act & Assert
        assertNotEquals(details1, details2);
    }

    @Test
    void testEquals_NullObject() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(request);

        // Act & Assert
        assertNotEquals(null, details);
    }

    @Test
    void testEquals_DifferentClass() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(request);
        String otherObject = "not a CustomWebAuthenticationDetails";

        // Act & Assert
        assertNotEquals(details, otherObject);
    }

    @Test
    void testToString_WithAllFields() {
        // Arrange
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(
            "192.168.1.100",
            "SESSION-123",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "en-US,en;q=0.9",
            "https://example.com/login"
        );

        // Act
        String result = details.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("CustomWebAuthenticationDetails"));
        assertTrue(result.contains("RemoteIpAddress=192.168.1.100"));
        assertTrue(result.contains("SessionId=SESSION-123"));
        assertTrue(result.contains("UserAgent="));
        assertTrue(result.contains("AcceptLanguage=en-US,en;q=0.9"));
        assertTrue(result.contains("Referer=https://example.com/login"));
    }

    @Test
    void testToString_WithLongUserAgent() {
        // Arrange - Create a very long user agent string (>50 chars)
        String longUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                + "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(
            "192.168.1.100",
            "SESSION-123",
            longUserAgent,
            "en-US",
            "https://example.com"
        );

        // Act
        String result = details.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("UserAgent="));
        assertTrue(result.contains("..."), "Long user agent should be masked with '...'");
        assertFalse(result.contains(longUserAgent), "Full long user agent should not appear in toString");
    }

    @Test
    void testToString_WithNullFields() {
        // Arrange
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(
            "192.168.1.100",
            null,
            null,
            null,
            null
        );

        // Act
        String result = details.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("CustomWebAuthenticationDetails"));
        assertTrue(result.contains("RemoteIpAddress=192.168.1.100"));
        assertTrue(result.contains("SessionId=null"));
        assertTrue(result.contains("UserAgent=null"));
        assertTrue(result.contains("AcceptLanguage=null"));
        assertTrue(result.contains("Referer=null"));
    }

    @Test
    void testGetters() {
        // Arrange
        String remoteAddress = "203.0.113.1";
        String sessionId = "ABC123XYZ";
        String userAgent = "Custom-Client/1.0";
        String acceptLanguage = "de-DE,de;q=0.9";
        String referer = "https://test.example.com";

        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(
            remoteAddress,
            sessionId,
            userAgent,
            acceptLanguage,
            referer
        );

        // Act & Assert
        assertEquals(remoteAddress, details.getRemoteAddress());
        assertEquals(sessionId, details.getSessionId());
        assertEquals(userAgent, details.getUserAgent());
        assertEquals(acceptLanguage, details.getAcceptLanguage());
        assertEquals(referer, details.getReferer());
    }

    @Test
    void testHashCode_ConsistentWithEquals() {
        // Arrange
        CustomWebAuthenticationDetails details1 = new CustomWebAuthenticationDetails(
            "192.168.1.100",
            "SESSION-123",
            "Mozilla/5.0",
            "en-US",
            "https://example.com"
        );

        CustomWebAuthenticationDetails details2 = new CustomWebAuthenticationDetails(
            "192.168.1.100",
            "SESSION-123",
            "Mozilla/5.0",
            "en-US",
            "https://example.com"
        );

        // Act & Assert
        assertEquals(details1, details2);
        assertEquals(details1.hashCode(), details2.hashCode());
    }

    @Test
    void testMobileUserAgent() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.200");
        request.addHeader("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15");
        request.addHeader("Accept-Language", "en-US");

        // Act
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(request);

        // Assert
        assertNotNull(details.getUserAgent());
        assertTrue(details.getUserAgent().contains("iPhone"));
    }

    @Test
    void testTabletUserAgent() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.201");
        request.addHeader("User-Agent", "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15");

        // Act
        CustomWebAuthenticationDetails details = new CustomWebAuthenticationDetails(request);

        // Assert
        assertNotNull(details.getUserAgent());
        assertTrue(details.getUserAgent().contains("iPad"));
    }
}
