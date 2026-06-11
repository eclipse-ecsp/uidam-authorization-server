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

package org.eclipse.ecsp.oauth2.server.core.authentication.handlers;

import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.service.AuthorizationService;
import org.eclipse.ecsp.oauth2.server.core.service.ClientRegistrationManager;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseSecurityContextRepository;
import org.eclipse.ecsp.sql.multitenancy.TenantContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Comprehensive test class for LogoutHandler with full code coverage. Tests all scenarios including success cases,
 * error cases, and edge cases.
 */
@ExtendWith(MockitoExtension.class)
class LogoutHandlerTest {

    @Mock
    private AuthorizationService authorizationService;

    @Mock
    private ClientRegistrationManager clientRegistrationManager;

    @Mock
    private DatabaseSecurityContextRepository databaseSecurityContextRepository;

    @Mock
    private Authentication authentication;

    @Mock
    private OAuth2Authorization authorization;

    @Mock
    private RegisteredClient registeredClient;
    @Mock
    private OAuth2Authorization.Token<OAuth2AccessToken> accessToken;

    @Mock
    private OAuth2AccessToken oauth2AccessToken;

    private LogoutHandler logoutHandler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    private static final String TEST_CLIENT_ID = "testClient";
    private static final String TEST_ACCESS_TOKEN = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...";
    private static final String TEST_POST_LOGOUT_REDIRECT_URI = "https://client.example.com/logout-callback";
    private static final String TEST_STATE = "test-state-123";
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_PRINCIPAL_NAME = "testUser";
    private static final String TEST_AUTHORIZATION_ID = "auth-123";    
    
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        logoutHandler = new LogoutHandler(authorizationService, clientRegistrationManager,
                databaseSecurityContextRepository, mock(AuditLogger.class), "localhost,127.0.0.1");
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        
        // Initialize and enable multitenancy for tests
        TenantContext.initialize(true);
        // Set up tenant context for multi-tenancy tests
        
        TenantContext.setCurrentTenant("uidam");
    }

    @AfterEach
    void tearDown() {
        // Clean up tenant context after each test
        TenantContext.clear();
    }

    @Test
    void testOnLogoutSuccess_WithValidIdTokenHintAndRedirectUri_ShouldSucceed() throws IOException {
        // Arrange
        setupValidScenario();

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        verify(authorizationService).findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN));
        verify(authorizationService).revokenTokenByPrincipalAndClientId(TEST_PRINCIPAL_NAME, TEST_CLIENT_ID);
        verify(clientRegistrationManager).findByClientId(TEST_CLIENT_ID);
        verify(databaseSecurityContextRepository).unauthenticatedContextInDb(TEST_SESSION_ID);

        assertTrue(response.getRedirectedUrl().contains(TEST_POST_LOGOUT_REDIRECT_URI));
        assertTrue(response.getRedirectedUrl().contains("state=" + TEST_STATE));
    }

    @Test
    void testOnLogoutSuccess_WithoutIdTokenHint_ShouldSucceed() throws IOException {
        // Arrange
        setupValidRegisteredClient();

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, null, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        verify(authorizationService, never()).findByToken(anyString(), any());
        verify(authorizationService, never()).revokenTokenByPrincipalAndClientId(anyString(), anyString());
        verify(clientRegistrationManager).findByClientId(TEST_CLIENT_ID);

        assertTrue(response.getRedirectedUrl().contains(TEST_POST_LOGOUT_REDIRECT_URI));
        assertTrue(response.getRedirectedUrl().contains("state=" + TEST_STATE));
    }

    @Test
    void testOnLogoutSuccess_WithoutPostLogoutRedirectUri_ShouldRedirectToSuccessPage() throws IOException {
        // Arrange
        setupValidTokenScenario();

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID, null,
                TEST_STATE);
        // Assert
        verify(authorizationService).revokenTokenByPrincipalAndClientId(TEST_PRINCIPAL_NAME, TEST_CLIENT_ID);
        assertEquals("/uidam/oauth2/logout/success", response.getRedirectedUrl());
    }

    @Test
    void testOnLogoutSuccess_WithInvalidToken_ShouldRedirectToErrorPage() throws IOException {
        // Arrange
        when(authorizationService.findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(null);
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(TEST_POST_LOGOUT_REDIRECT_URI));

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        assertTrue(response.getRedirectedUrl().contains("error=invalid_token"));
        assertTrue(response.getRedirectedUrl().contains(TEST_POST_LOGOUT_REDIRECT_URI));
    }

    @Test
    void testOnLogoutSuccess_WithInvalidatedToken_ShouldRedirectToErrorPage() throws IOException {
        // Arrange
        setupInvalidatedTokenScenario();

        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(TEST_POST_LOGOUT_REDIRECT_URI));
        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        assertTrue(response.getRedirectedUrl().contains("error=invalid_token"));
        assertTrue(response.getRedirectedUrl().contains(TEST_POST_LOGOUT_REDIRECT_URI));
    }

    @Test
    void testOnLogoutSuccess_WithExpiredToken_ShouldRedirectToErrorPage() throws IOException {
        // Arrange
        setupExpiredTokenScenario();
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(TEST_POST_LOGOUT_REDIRECT_URI));

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        assertTrue(response.getRedirectedUrl().contains("error=invalid_token"));
        assertTrue(response.getRedirectedUrl().contains(TEST_POST_LOGOUT_REDIRECT_URI));
    }

    @Test
    void testOnLogoutSuccess_WithMismatchedClientId_ShouldRedirectToErrorPage() throws IOException {
        // Arrange - Set up only what's needed for this test
        when(authorizationService.findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(authorization.getId()).thenReturn(TEST_AUTHORIZATION_ID);
        when(authorization.getAccessToken()).thenReturn(accessToken);
        when(authorization.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
        when(authorization.getRegisteredClientId()).thenReturn(TEST_CLIENT_ID);
        when(accessToken.isInvalidated()).thenReturn(false);
        when(accessToken.isExpired()).thenReturn(false);
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(TEST_POST_LOGOUT_REDIRECT_URI));
        
        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, "differentClientId",
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        assertTrue(response.getRedirectedUrl().contains("error=invalid_client"));
        assertTrue(response.getRedirectedUrl().contains("/uidam/oauth2/logout/error"));
    }

    @Test
    void testOnLogoutSuccess_WithInvalidPostLogoutRedirectUri_ShouldRedirectToSuccessPage() throws IOException {
        // Arrange
        setupValidTokenScenario();

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                "https://malicious.example.com", TEST_STATE);

        // Assert
        assertEquals("/uidam/oauth2/logout/success", response.getRedirectedUrl());
    }

    @Test
    void testOnLogoutSuccess_WithAccessTokenWithoutBearerPrefix_ShouldSucceed() throws IOException {
        // Arrange
        setupValidScenario();
        String tokenWithoutBearer = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."; // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, tokenWithoutBearer, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        verify(authorizationService).findByToken(tokenWithoutBearer, OAuth2TokenType.ACCESS_TOKEN);
        assertTrue(response.getRedirectedUrl().contains(TEST_POST_LOGOUT_REDIRECT_URI));
    }

    @Test
    void testOnLogoutSuccess_WithOauthException_ShouldHandleError() throws IOException {
        // Arrange
        when(authorizationService.findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN)))
                .thenThrow(new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "Invalid token", null)));
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(TEST_POST_LOGOUT_REDIRECT_URI));

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        assertTrue(response.getRedirectedUrl().contains("error=invalid_token"));
        assertTrue(response.getRedirectedUrl().contains(TEST_POST_LOGOUT_REDIRECT_URI));
    }

    @Test
    void testOnLogoutSuccess_WithUnexpectedException_ShouldHandleServerError() throws IOException {
        // Arrange
        when(authorizationService.findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN)))
                .thenThrow(new RuntimeException("Database connection failed"));
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(TEST_POST_LOGOUT_REDIRECT_URI));

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        assertTrue(response.getRedirectedUrl().contains("error=server_error"));
        assertTrue(response.getRedirectedUrl().contains(TEST_POST_LOGOUT_REDIRECT_URI));
    }

    @Test
    void testOnLogoutSuccess_WithErrorAndNoPostLogoutRedirectUri_ShouldRedirectToErrorPage() throws IOException {
        // Arrange
        when(authorizationService.findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN)))
                .thenThrow(new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "Invalid token", null)));

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID, null,
                TEST_STATE);

        // Assert
        assertTrue(response.getRedirectedUrl().contains("/uidam/oauth2/logout/error"));
        assertTrue(response.getRedirectedUrl().contains("error=invalid_token"));
    }

    @Test
    void testOnLogoutSuccess_WithInsecureRedirectUri_ShouldRedirectToErrorPage() throws IOException {
        // Arrange
        setupValidTokenScenario();
        String insecureUri = "javascript:alert('xss')";
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(insecureUri));

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID, insecureUri,
                TEST_STATE);

        // Assert
        assertEquals("/uidam/oauth2/logout/error?error=server_error", response.getRedirectedUrl());
    }

    @Test
    void testOnLogoutSuccess_WithHttpLocalhostRedirectUri_ShouldSucceed() throws IOException {
        // Arrange
        setupValidTokenScenario();
        String localhostUri = "http://localhost:3000/callback";
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(localhostUri));
        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                localhostUri, TEST_STATE);

        // Assert
        assertTrue(response.getRedirectedUrl().contains(localhostUri));
    }

    @Test
    void testOnLogoutSuccess_WithHttp127RedirectUri_ShouldSucceed() throws IOException {
        // Arrange
        setupValidTokenScenario();
        String localhostUri = "http://127.0.0.1:3000/callback";
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(localhostUri));

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                localhostUri, TEST_STATE);

        // Assert
        assertTrue(response.getRedirectedUrl().contains(localhostUri));
    }

    @Test
    void testOnLogoutSuccess_WithRelativeRedirectUri_ShouldSucceed() throws IOException {
        // Arrange
        setupValidTokenScenario();
        String relativeUri = "/logout-success";
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(relativeUri));

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID, relativeUri,
                TEST_STATE);

        // Assert
        assertTrue(response.getRedirectedUrl().contains(relativeUri));
    }

    @Test
    void testOnLogoutSuccess_WithClientNotFound_ShouldRedirectToSuccessPage() throws IOException {
        // Arrange
        setupValidTokenScenario();
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(null);

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        assertEquals("/uidam/oauth2/logout/success", response.getRedirectedUrl());
    }

    @Test
    void testOnLogoutSuccess_WithRegisteredClientRepositoryException_ShouldRedirectToSuccessPage() throws IOException {
        // Arrange
        setupValidTokenScenario();
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID))
                .thenThrow(new RuntimeException("Database error"));

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);
        // Assert
        assertEquals("/uidam/oauth2/logout/success", response.getRedirectedUrl());
    }

    @Test
    void testOnLogoutSuccess_WithSessionInvalidationException_ShouldContinueProcessing() {
        // Arrange - Set up only what's needed for this test
        when(authorizationService.findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(authorization.getId()).thenReturn(TEST_AUTHORIZATION_ID);
        when(authorization.getAccessToken()).thenReturn(accessToken);
        when(authorization.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
        when(authorization.getRegisteredClientId()).thenReturn(TEST_CLIENT_ID);
        when(accessToken.isInvalidated()).thenReturn(false);

        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(TEST_POST_LOGOUT_REDIRECT_URI));

        // Create a mock session that throws exception on invalidate
        HttpSession mockSession = mock(HttpSession.class);
        when(mockSession.getId()).thenReturn(TEST_SESSION_ID);
        doThrow(new RuntimeException("Session error")).when(mockSession).invalidate();

        request.setSession(mockSession);

        // Act & Assert - Should not throw exception
        assertDoesNotThrow(() -> {
            logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                    TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);
        });

        assertTrue(response.getRedirectedUrl().contains(TEST_POST_LOGOUT_REDIRECT_URI));
    }

    @Test
    void testOnLogoutSuccess_WithDatabaseSecurityContextException_ShouldContinueProcessing() {
        // Arrange
        setupValidScenario();
        doThrow(new RuntimeException("Database error")).when(databaseSecurityContextRepository)
                .unauthenticatedContextInDb(anyString());

        // Act & Assert - Should not throw exception
        assertDoesNotThrow(() -> {
            logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                    TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);
        });

        assertTrue(response.getRedirectedUrl().contains(TEST_POST_LOGOUT_REDIRECT_URI));
    }

    @Test
    void testOnLogoutSuccess_WithNoSession_ShouldContinueProcessing() throws IOException {
        // Arrange - Set up valid token and client scenarios without session
        when(authorizationService.findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(authorization.getId()).thenReturn(TEST_AUTHORIZATION_ID);
        when(authorization.getAccessToken()).thenReturn(accessToken);
        when(authorization.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
        when(authorization.getRegisteredClientId()).thenReturn(TEST_CLIENT_ID);
        when(accessToken.isInvalidated()).thenReturn(false);

        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(TEST_POST_LOGOUT_REDIRECT_URI));

        // Explicitly set session to null
        request.setSession(null);

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        verify(databaseSecurityContextRepository, never()).unauthenticatedContextInDb(anyString());
        assertTrue(response.getRedirectedUrl().contains(TEST_POST_LOGOUT_REDIRECT_URI));
    }

    @Test
    void testOnLogoutSuccess_WithEmptyClientId_ShouldSucceed() throws IOException {
        // Arrange
        setupValidTokenScenarioWithoutClientIdValidation();

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, "",
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        assertEquals("/uidam/oauth2/logout/success", response.getRedirectedUrl());
    }

    @Test
    void testOnLogoutSuccess_WithEmptyPostLogoutRedirectUri_ShouldSucceed() throws IOException {
        // Arrange
        setupValidTokenScenario();

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID, "",
                TEST_STATE);

        // Assert
        assertEquals("/uidam/oauth2/logout/success", response.getRedirectedUrl());
    }

    @Test
    void testOnLogoutSuccess_WithWhitespaceOnlyClientId_ShouldSucceed() throws IOException {
        // Arrange
        setupValidTokenScenarioWithoutClientIdValidation();

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, "   ",
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);

        // Assert
        assertEquals("/uidam/oauth2/logout/success", response.getRedirectedUrl());
    }

    @Test
    void testOnLogoutSuccess_WithErrorDescriptionEncoding_ShouldProperlyEncodeUrl() throws IOException {
        String error = "Error with special characters: spaces & symbols!";
        when(authorizationService.findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN))).thenThrow(
                new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, error, null)));
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(TEST_POST_LOGOUT_REDIRECT_URI));

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                TEST_POST_LOGOUT_REDIRECT_URI, TEST_STATE);
        String encoded = URLEncoder.encode(error, "UTF-8");

        // Assert
        String redirectUrl = response.getRedirectedUrl();
        assertTrue(redirectUrl.contains("error=invalid_token"));
        assertTrue(redirectUrl.contains("error_description=" + encoded));
        assertTrue(redirectUrl.contains(TEST_POST_LOGOUT_REDIRECT_URI));
    }

    @Test
    void testOnLogoutSuccess_WithMalformedRedirectUri_ShouldRedirectToErrorPage() throws IOException {
        // Arrange
        setupValidTokenScenario();
        String malformedUri = "not-a-valid-uri with spaces";
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(malformedUri));

        // Act
        logoutHandler.onLogoutSuccess(request, response, authentication, TEST_ACCESS_TOKEN, TEST_CLIENT_ID,
                malformedUri, TEST_STATE);

        // Assert
        assertEquals("/uidam/oauth2/logout/error?error=server_error", response.getRedirectedUrl());
    }

    // Helper methods for setting up test scenarios

    private void setupValidScenario() {
        setupValidTokenScenario();
        setupValidRegisteredClient();
        HttpSession mockSession = mock(HttpSession.class);
        when(mockSession.getId()).thenReturn(TEST_SESSION_ID);
        request.setSession(mockSession);
    }

    private void setupValidTokenScenario() {
        setupValidTokenScenarioWithoutClientIdValidation();
        when(authorization.getRegisteredClientId()).thenReturn(TEST_CLIENT_ID);
    }

    private void setupValidTokenScenarioWithoutClientIdValidation() {
        when(authorizationService.findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(authorization.getId()).thenReturn(TEST_AUTHORIZATION_ID);
        when(authorization.getAccessToken()).thenReturn(accessToken);
        when(authorization.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
        when(authorization.getPrincipalName()).thenReturn(TEST_PRINCIPAL_NAME);
        when(accessToken.isInvalidated()).thenReturn(false);
        when(accessToken.isExpired()).thenReturn(false);

        HttpSession mockSession = mock(HttpSession.class);
        request.setSession(mockSession);
    }

    private void setupValidRegisteredClient() {
        when(clientRegistrationManager.findByClientId(TEST_CLIENT_ID)).thenReturn(registeredClient);
        when(registeredClient.getPostLogoutRedirectUris()).thenReturn(Set.of(TEST_POST_LOGOUT_REDIRECT_URI));
    }

    private void setupInvalidatedTokenScenario() {
        when(authorizationService.findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(authorization.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
        when(authorization.getAccessToken()).thenReturn(accessToken);
        when(accessToken.isInvalidated()).thenReturn(true);
    }

    private void setupExpiredTokenScenario() {
        when(authorizationService.findByToken(anyString(), eq(OAuth2TokenType.ACCESS_TOKEN))).thenReturn(authorization);
        when(authorization.getAccessToken()).thenReturn(accessToken);
        when(authorization.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
        when(accessToken.isInvalidated()).thenReturn(false);
        when(accessToken.isExpired()).thenReturn(true);
    }
}
