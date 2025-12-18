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

package org.eclipse.ecsp.oauth2.server.core.authentication.filters;

import jakarta.servlet.ServletException;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.io.IOException;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_USER_NAME;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;

/**
 * This class tests the functionality of the CustomUserPwdAuthenticationFilter.
 */
@SpringBootTest
@ContextConfiguration(classes = { CustomUserPwdAuthenticationFilter.class })
class CustomUserPwdAuthenticationFilterTest {

    @Autowired
    CustomUserPwdAuthenticationFilter customUserPwdAuthenticationFilter;

    @MockitoBean
    AuthenticationManager authenticationManager;

    @MockitoBean
    TenantConfigurationService tenantConfigurationService;

    @MockitoBean
    AuthorizationMetricsService authorizationMetricsService;

    @MockitoBean
    AuditLogger auditLogger;

    MockHttpServletRequest mockHttpServletRequest;
    MockHttpServletResponse mockHttpServletResponse;

    /**
     * This method sets up the test environment before each test.
     * It initializes the mock HttpServletRequest and HttpServletResponse.
     */
    @BeforeEach
    void setUp() {
        mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletResponse = new MockHttpServletResponse();
    }

    /**
     * This method tests the scenario where the authentication attempt is successful.
     * It sets up the necessary parameters in the mock HttpServletRequest and then calls the attemptAuthentication
     * method.
     * The test asserts that the returned Authentication object is not null.
     */
    @Test
    void testAttemptAuthenticationSuccess() throws ServletException, IOException {
        mockHttpServletRequest.setMethod("POST");
        mockHttpServletRequest.addParameter("username", TEST_USER_NAME);
        mockHttpServletRequest.addParameter("password", TEST_PASSWORD);
        mockHttpServletRequest.addParameter("account_name", TEST_ACCOUNT_NAME);
        CustomUserPwdAuthenticationToken customUserPwdAuthenticationToken =
            new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD, TEST_ACCOUNT_NAME);
        doReturn(customUserPwdAuthenticationToken).when(authenticationManager).authenticate(any());
        Authentication authentication = customUserPwdAuthenticationFilter.attemptAuthentication(mockHttpServletRequest,
            mockHttpServletResponse);
        assertNotNull(authentication);
    }

    /**
     * This method tests the scenario where the fields in the authentication request are null.
     * It sets up the necessary parameters in the mock HttpServletRequest and then calls the attemptAuthentication
     * method.
     * The test asserts that the returned Authentication object is not null.
     */
    @Test
    void testAttemptAuthenticationFieldsNull() throws ServletException, IOException {
        mockHttpServletRequest.setMethod("POST");
        CustomUserPwdAuthenticationToken customUserPwdAuthenticationToken =
            new CustomUserPwdAuthenticationToken(null, null, null);
        doReturn(customUserPwdAuthenticationToken).when(authenticationManager).authenticate(any());
        Authentication authentication = customUserPwdAuthenticationFilter.attemptAuthentication(mockHttpServletRequest,
            mockHttpServletResponse);
        assertNotNull(authentication);
    }

    /**
     * This method tests the scenario where the request method is null.
     * It calls the attemptAuthentication method and expects an AuthenticationServiceException to be thrown.
     */
    @Test
    void testAttemptAuthenticationRequestMethodNull() {
        assertThrows(AuthenticationServiceException.class,
                () -> customUserPwdAuthenticationFilter.attemptAuthentication(mockHttpServletRequest,
                    mockHttpServletResponse));
    }

}