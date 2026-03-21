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

package org.eclipse.ecsp.oauth2.server.core.authentication.handlers;

import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseSecurityContextRepository;
import org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations;
import org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.security.Principal;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_USER_NAME;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the CustomRevocationSuccessHandler.
 */
class CustomRevocationSuccessHandlerTest {

    private CustomRevocationSuccessHandler successHandler;
    @Mock
    OAuth2AuthorizationService oauth2AuthorizationService;
    @Mock
    DatabaseSecurityContextRepository databaseSecurityContextRepository;
    @Mock
    AuditLogger auditLogger;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    /**
     * This method sets up the test environment before each test.
     * It initializes the CustomRevocationSuccessHandler and the mock HttpServletRequest and HttpServletResponse.
     */
    @BeforeEach
    void setUp() {
        this.oauth2AuthorizationService = mock(OAuth2AuthorizationService.class);
        this.databaseSecurityContextRepository = mock(DatabaseSecurityContextRepository.class);
        this.auditLogger = mock(AuditLogger.class);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        successHandler = new CustomRevocationSuccessHandler(oauth2AuthorizationService,
            databaseSecurityContextRepository, auditLogger);
    }

    /**
     * This method tests the scenario where the authentication is successful.
     * It sets up the necessary parameters and then calls the onAuthenticationSuccess method.
     * The test asserts that no exception is thrown and that the unauthenticatedContextInDb method of the
     * DatabaseSecurityContextRepository is called once.
     */
    @Test
     void testOnAuthenticationSuccess() {
        RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient)
            .attributes(a -> {
                CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
                    TEST_PASSWORD, null, null);
                WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails("", "");
                authentication.setDetails(webAuthenticationDetails);
                a.put(Principal.class.getName(), authentication);
            }).build();
        when(oauth2AuthorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).thenReturn(authorization);

        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
            registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2TokenRevocationAuthenticationToken authenticationToken = new
            OAuth2TokenRevocationAuthenticationToken(authorization.getAccessToken().getToken().getTokenValue(),
            clientPrincipal, null);
        assertDoesNotThrow(() -> this.successHandler.onAuthenticationSuccess(this.request, this.response,
            authenticationToken));
        verify(databaseSecurityContextRepository, times(1)).unauthenticatedContextInDb(anyString());
    }

    /**
     * This method tests the scenario where the findByToken method returns null.
     * It sets up the necessary parameters and then calls the onAuthenticationSuccess method.
     * The test asserts that no exception is thrown, that the unauthenticatedContextInDb method of the
     * DatabaseSecurityContextRepository is not called, and that the audit logger IS called
     * with AUTHZ_FAILURE_REVOKED_TOKEN.
     */
    @Test
    void testOnAuthenticationFindByTokenNull() {
        RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        when(oauth2AuthorizationService.findByToken(anyString(), any())).thenReturn(null);

        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
            registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2TokenRevocationAuthenticationToken authenticationToken = new
            OAuth2TokenRevocationAuthenticationToken(authorization.getAccessToken().getToken().getTokenValue(),
            clientPrincipal, null);
        assertDoesNotThrow(() -> this.successHandler.onAuthenticationSuccess(this.request, this.response,
            authenticationToken));
        verify(databaseSecurityContextRepository, times(0)).unauthenticatedContextInDb(anyString());
        // Verify audit logger was called with AUTHZ_FAILURE_REVOKED_TOKEN
        verify(auditLogger, times(1)).log(
            eq("AUTHZ_FAILURE_REVOKED_TOKEN"),
            eq("UIDAM_AUTHORIZATION_SERVER"),
            any(),
            eq("Authorization failed - token has been revoked"),
            any(),
            any()
        );
    }

    /**
     * This method tests the scenario where the authentication token is null.
     * It sets up the necessary parameters and then calls the onAuthenticationSuccess method.
     * The test asserts that no exception is thrown and that the unauthenticatedContextInDb method of the
     * DatabaseSecurityContextRepository is not called.
     */
    @Test
    void testAuthenticateAuthTokenNull() {
        RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient)
            .attributes(a -> {
                a.put(Principal.class.getName(), null);
            }).build();
        when(oauth2AuthorizationService.findByToken(anyString(), any())).thenReturn(authorization);

        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
            registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2TokenRevocationAuthenticationToken authenticationToken = new
            OAuth2TokenRevocationAuthenticationToken(authorization.getAccessToken().getToken().getTokenValue(),
            clientPrincipal, null);
        assertDoesNotThrow(() -> this.successHandler.onAuthenticationSuccess(this.request, this.response,
            authenticationToken));
        verify(databaseSecurityContextRepository, times(0)).unauthenticatedContextInDb(anyString());
    }

}