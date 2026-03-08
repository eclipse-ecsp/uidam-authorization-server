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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link CustomWebAuthenticationDetailsSource}.
 *
 * @author UIDAM Team
 */
class CustomWebAuthenticationDetailsSourceTest {

    private CustomWebAuthenticationDetailsSource detailsSource;

    @BeforeEach
    void setUp() {
        detailsSource = new CustomWebAuthenticationDetailsSource();
    }

    @Test
    void testBuildDetails_WithAllHeaders() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.100");
        request.addHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        request.addHeader("Accept-Language", "en-US,en;q=0.9");
        request.addHeader("Referer", "https://example.com/login");
        request.setSession(new MockHttpSession(null, "TEST-SESSION-123"));

        // Act
        WebAuthenticationDetails details = detailsSource.buildDetails(request);

        // Assert
        assertNotNull(details);
        assertInstanceOf(CustomWebAuthenticationDetails.class, details);
        
        CustomWebAuthenticationDetails customDetails = (CustomWebAuthenticationDetails) details;
        assertEquals("192.168.1.100", customDetails.getRemoteAddress());
        assertEquals("TEST-SESSION-123", customDetails.getSessionId());
        assertEquals("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", customDetails.getUserAgent());
        assertEquals("en-US,en;q=0.9", customDetails.getAcceptLanguage());
        assertEquals("https://example.com/login", customDetails.getReferer());
    }

    @Test
    void testBuildDetails_WithMissingHeaders() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");

        // Act
        WebAuthenticationDetails details = detailsSource.buildDetails(request);

        // Assert
        assertNotNull(details);
        assertInstanceOf(CustomWebAuthenticationDetails.class, details);
        
        CustomWebAuthenticationDetails customDetails = (CustomWebAuthenticationDetails) details;
        assertEquals("10.0.0.1", customDetails.getRemoteAddress());
        assertNull(customDetails.getSessionId());
        assertNull(customDetails.getUserAgent());
        assertNull(customDetails.getAcceptLanguage());
        assertNull(customDetails.getReferer());
    }

    @Test
    void testBuildDetails_WithPartialHeaders() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("172.16.0.1");
        request.addHeader("User-Agent", "PostmanRuntime/7.36.0");
        // Missing Accept-Language and Referer

        // Act
        WebAuthenticationDetails details = detailsSource.buildDetails(request);

        // Assert
        assertNotNull(details);
        assertInstanceOf(CustomWebAuthenticationDetails.class, details);
        
        CustomWebAuthenticationDetails customDetails = (CustomWebAuthenticationDetails) details;
        assertEquals("172.16.0.1", customDetails.getRemoteAddress());
        assertEquals("PostmanRuntime/7.36.0", customDetails.getUserAgent());
        assertNull(customDetails.getAcceptLanguage());
        assertNull(customDetails.getReferer());
    }

    @Test
    void testBuildDetails_MobileUserAgent() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.50");
        request.addHeader("User-Agent", 
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15");
        request.addHeader("Accept-Language", "en-US");

        // Act
        WebAuthenticationDetails details = detailsSource.buildDetails(request);

        // Assert
        assertNotNull(details);
        CustomWebAuthenticationDetails customDetails = (CustomWebAuthenticationDetails) details;
        assertTrue(customDetails.getUserAgent().contains("iPhone"));
    }

    @Test
    void testBuildDetails_DifferentLanguages() {
        // Arrange
        MockHttpServletRequest request1 = new MockHttpServletRequest();
        request1.addHeader("Accept-Language", "fr-FR,fr;q=0.9");
        
        MockHttpServletRequest request2 = new MockHttpServletRequest();
        request2.addHeader("Accept-Language", "de-DE,de;q=0.9,en;q=0.8");

        // Act
        CustomWebAuthenticationDetails details1 = detailsSource.buildDetails(request1);
        CustomWebAuthenticationDetails details2 = detailsSource.buildDetails(request2);

        // Assert
        assertEquals("fr-FR,fr;q=0.9", details1.getAcceptLanguage());
        assertEquals("de-DE,de;q=0.9,en;q=0.8", details2.getAcceptLanguage());
    }

    @Test
    void testBuildDetails_MultipleCallsReturnDifferentInstances() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.100");
        request.addHeader("User-Agent", "Test-Agent");

        // Act
        CustomWebAuthenticationDetails details1 = detailsSource.buildDetails(request);
        CustomWebAuthenticationDetails details2 = detailsSource.buildDetails(request);

        // Assert
        assertNotSame(details1, details2, "Each call should return a new instance");
        assertEquals(details1, details2, "But instances should be equal");
    }

    @Test
    void testBuildDetails_WithSessionCreated() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.100");
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        // Act
        CustomWebAuthenticationDetails details = detailsSource.buildDetails(request);

        // Assert
        assertNotNull(details);
        assertEquals(session.getId(), details.getSessionId());
    }

    @Test
    void testBuildDetails_WithEmptyHeaders() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.100");
        request.addHeader("User-Agent", "");
        request.addHeader("Accept-Language", "");
        request.addHeader("Referer", "");

        // Act
        CustomWebAuthenticationDetails details = detailsSource.buildDetails(request);

        // Assert
        assertNotNull(details);
        assertEquals("", details.getUserAgent());
        assertEquals("", details.getAcceptLanguage());
        assertEquals("", details.getReferer());
    }

    @Test
    void testBuildDetails_ChromeBrowser() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.101");
        request.addHeader("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                + "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

        // Act
        CustomWebAuthenticationDetails details = detailsSource.buildDetails(request);

        // Assert
        assertNotNull(details.getUserAgent());
        assertTrue(details.getUserAgent().contains("Chrome"));
    }

    @Test
    void testBuildDetails_FirefoxBrowser() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.102");
        request.addHeader("User-Agent", 
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0");

        // Act
        CustomWebAuthenticationDetails details = detailsSource.buildDetails(request);

        // Assert
        assertNotNull(details.getUserAgent());
        assertTrue(details.getUserAgent().contains("Firefox"));
    }

    @Test
    void testBuildDetails_SafariBrowser() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.103");
        request.addHeader("User-Agent",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 "
                + "(KHTML, like Gecko) Version/17.1 Safari/605.1.15");

        // Act
        CustomWebAuthenticationDetails details = detailsSource.buildDetails(request);

        // Assert
        assertNotNull(details.getUserAgent());
        assertTrue(details.getUserAgent().contains("Safari"));
    }

    @Test
    void testBuildDetails_ApiClient() {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.104");
        request.addHeader("User-Agent", "curl/8.4.0");

        // Act
        CustomWebAuthenticationDetails details = detailsSource.buildDetails(request);

        // Assert
        assertNotNull(details.getUserAgent());
        assertTrue(details.getUserAgent().contains("curl"));
    }
}
