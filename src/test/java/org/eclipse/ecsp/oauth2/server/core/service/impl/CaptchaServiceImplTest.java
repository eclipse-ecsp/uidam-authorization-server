/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.service.impl;

import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.CaptchaProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.ReCaptchaInvalidException;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.sql.multitenancy.TenantContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.reactive.function.client.WebClientRequestException;

import java.util.stream.Stream;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.RECAPTCHA_URL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the CaptchaServiceImpl.
 */
@ExtendWith(MockitoExtension.class)
class CaptchaServiceImplTest {

    @InjectMocks
    CaptchaServiceImpl captchaService;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private AuthorizationMetricsService authorizationMetricsService;

    @Mock
    private TenantProperties tenantProperties;

    @Mock
    private HttpServletRequest httpServletRequest;

    /**
     * This method sets up the test environment before each test.
     * It initializes the mocks and sets up tenant context.
     */
    @BeforeEach
    void setup() {
        TenantContext.setCurrentTenant("ecsp");
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    /**
     * This test method tests the scenario where an unknown host is passed to the WebClient.
     * It sets up the necessary parameters and then calls the processResponse method.
     * The test asserts that a WebClientRequestException is thrown.
     */
    @Test
    void testWebClientExceptionWhenUnknownHostIsPassed() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getCaptcha()).thenReturn(mock(CaptchaProperties.class));
        when(tenantProperties.getCaptcha().getRecaptchaVerifyUrl()).thenReturn("verifyUrl");
        String recaptchaResponse = "recaptcha";
        assertThrows(WebClientRequestException.class, () -> {
            captchaService.processResponse(recaptchaResponse, httpServletRequest);
        });

    }

    /**
     * This test method tests the scenario where an invalid captcha is passed.
     * It sets up the necessary parameters and then calls the processResponse method.
     * The test asserts that a ReCaptchaInvalidException is thrown.
     */
    @Test
    void testReCaptchaUnavailableExceptionWhenInvalidCaptchaIsPassed() {
        String recaptchaResponse = "$$";
        assertThrows(ReCaptchaInvalidException.class, () -> {
            captchaService.processResponse(recaptchaResponse, httpServletRequest);
        });
    }

    /**
     * This test method tests the scenario where the recaptcha is not validated.
     * It sets up the necessary parameters and then calls the processResponse method.
     * The test asserts that a ReCaptchaInvalidException is thrown.
     */
    @Test
    void testProcessResponseExceptionWhenRecaptchaNotValidated() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getCaptcha()).thenReturn(mock(CaptchaProperties.class));
        when(tenantProperties.getCaptcha().getRecaptchaVerifyUrl()).thenReturn(RECAPTCHA_URL);
        String recaptchaResponse = "recaptcha";
        assertThrows(ReCaptchaInvalidException.class,
            () -> captchaService.processResponse(recaptchaResponse, httpServletRequest));
    }

    /**
     * This test method tests the scenario where valid recaptcha properties are passed.
     * It sets up the necessary parameters and then calls the getReCaptchaSite method.
     * The test asserts that the returned reCaptchaSite is equal to the provided keySite.
     */
    @Test
    void testExceptionWhenValidRecaptchaProps() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getCaptcha()).thenReturn(mock(CaptchaProperties.class));
        when(tenantProperties.getCaptcha().getRecaptchaKeySite()).thenReturn("keySite");
        String reCaptchaSite = captchaService.getReCaptchaSite();
        assertEquals("keySite", reCaptchaSite);
    }

    /**
     * This test method tests the response sanity check functionality.
     * It sets up the necessary parameters and then calls the responseSanityCheck method.
     * The test asserts that the returned response is true.
     */
    @Test
    void testResponseSanityCheck() {
        boolean response = captchaService.responseSanityCheck("recaptcha-response");
        assertTrue(response);
    }

    /**
     * Provides arguments for parameterized getClientIp tests.
     */
    static Stream<Arguments> provideClientIpArgs() {
        return Stream.of(
            Arguments.of("xforwardedfor", "xforwarded", "xforwardedfor"),
            Arguments.of(null, "192.168.1.1", "192.168.1.1"),
            Arguments.of("", "10.0.0.1", "10.0.0.1"),
            Arguments.of("10.0.0.1,10.0.0.2,10.0.0.3", "10.0.0.1", "10.0.0.1")
        );
    }

    /**
     * Test getClientIp with various X-Forwarded-For header and remoteAddr combinations.
     */
    @ParameterizedTest
    @MethodSource("provideClientIpArgs")
    void testGetClientIp(String headerValue, String remoteAddr, String expectedIp) {
        when(httpServletRequest.getHeader(anyString())).thenReturn(headerValue);
        when(httpServletRequest.getRemoteAddr()).thenReturn(remoteAddr);
        String response = captchaService.getClientIp(httpServletRequest);
        assertEquals(expectedIp, response);
    }

    /**
     * Test getReCaptchaSecret returns the configured secret key.
     */
    @Test
    void testGetReCaptchaSecret() {
        CaptchaProperties captchaProps = org.mockito.Mockito.mock(CaptchaProperties.class);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getCaptcha()).thenReturn(captchaProps);
        when(captchaProps.getRecaptchaKeySecret()).thenReturn("secretKey123");
        String secret = captchaService.getReCaptchaSecret();
        assertEquals("secretKey123", secret);
    }

    /**
     * Test responseSanityCheck returns false for invalid characters.
     */
    @Test
    void testResponseSanityCheckWithInvalidChars() {
        boolean response = captchaService.responseSanityCheck("$$invalid$$");
        org.junit.jupiter.api.Assertions.assertFalse(response);
    }

    /**
     * Test responseSanityCheck returns false for empty string.
     */
    @Test
    void testResponseSanityCheckWithEmpty() {
        boolean response = captchaService.responseSanityCheck("");
        org.junit.jupiter.api.Assertions.assertFalse(response);
    }

}