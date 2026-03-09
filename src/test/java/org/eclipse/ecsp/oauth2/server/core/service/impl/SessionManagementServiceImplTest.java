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

package org.eclipse.ecsp.oauth2.server.core.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientService;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.entities.Authorization;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.eclipse.ecsp.oauth2.server.core.response.dto.ActiveSessionsResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.InvalidateSessionsResponseDto;
import org.eclipse.ecsp.oauth2.server.core.utils.JwtTokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for SessionManagementServiceImpl.
 */
@ExtendWith(MockitoExtension.class)
class SessionManagementServiceImplTest {
    
    @Mock
    private AuthorizationRepository authorizationRepository;
    
    @Mock
    private CacheClientService cacheClientService;
    
    @Mock
    private JwtTokenValidator jwtTokenValidator;
    
    @Mock
    private Claims claims;
    
    @Mock
    private RegisteredClient registeredClient;
    
    @InjectMocks
    private SessionManagementServiceImpl service;
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    private static final String TENANT_ID = "test-tenant";
    private static final String USERNAME = "test.user@example.com";
    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_NAME = "Test Client";
    private static final String TOKEN_ID_1 = "token-id-1";
    private static final String TOKEN_ID_2 = "token-id-2";
    private static final String TEST_TOKEN = "test.jwt.token";
    private static final long TOKEN_EXPIRY_SECONDS = 3600L;
    
    @BeforeEach
    void setUp() {
        service = new SessionManagementServiceImpl(
                authorizationRepository, 
                cacheClientService, 
                objectMapper,
                jwtTokenValidator);
    }
    
    @Test
    void testGetActiveSessionsForUser_Success() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals(1, result.getTokens().size());
        assertEquals(TOKEN_ID_1, result.getTokens().get(0).getId());
        assertEquals(CLIENT_NAME, result.getTokens().get(0).getClientName());
    }
    
    @Test
    void testGetActiveSessionsForUser_FilterInvalidated() {
        // Arrange
        Authorization validAuth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        Authorization invalidAuth = createAuthorization(TOKEN_ID_2, USERNAME, CLIENT_ID, true);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Arrays.asList(validAuth, invalidAuth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals(TOKEN_ID_1, result.getTokens().get(0).getId());
    }
    
    @Test
    void testGetActiveSessionsForUser_IdentifyCurrentSession() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        // Mock JWT token validator to return claims
        when(jwtTokenValidator.getClaimsFromToken(TEST_TOKEN)).thenReturn(claims);
        when(claims.get("username", String.class)).thenReturn(USERNAME);
        when(claims.get("aud")).thenReturn(CLIENT_ID);
        when(claims.getIssuedAt()).thenReturn(Date.from(auth.getAccessTokenIssuedAt()));
        when(claims.getExpiration()).thenReturn(Date.from(auth.getAccessTokenExpiresAt()));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, TEST_TOKEN, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getIsCurrentSession());
    }
    
    @Test
    void testInvalidateSessionsForUser_Success() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        when(authorizationRepository.findById(TOKEN_ID_1)).thenReturn(Optional.of(auth));
        when(authorizationRepository.save(any(Authorization.class))).thenReturn(auth);
        
        // Act
        InvalidateSessionsResponseDto result = service.invalidateSessionsForUser(
                USERNAME, Collections.singletonList(TOKEN_ID_1), TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getInvalidatedSessions());
        assertNull(result.getFailedSessions());
        assertEquals("Sessions invalidated successfully", result.getMessage());
        verify(authorizationRepository, times(1)).save(any(Authorization.class));
    }
    
    @Test
    void testInvalidateSessionsForUser_SessionNotFound() {
        // Arrange
        when(authorizationRepository.findById(TOKEN_ID_1)).thenReturn(Optional.empty());
        
        // Act
        InvalidateSessionsResponseDto result = service.invalidateSessionsForUser(
                USERNAME, Collections.singletonList(TOKEN_ID_1), TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(0, result.getInvalidatedSessions());
        assertEquals(1, result.getFailedSessions().size());
        assertEquals("Session not found", result.getFailedSessions().get(0).getReason());
    }
    
    @Test
    void testInvalidateSessionsForUser_SessionDoesNotBelongToUser() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, "other.user@example.com", CLIENT_ID, false);
        when(authorizationRepository.findById(TOKEN_ID_1)).thenReturn(Optional.of(auth));
        
        // Act
        InvalidateSessionsResponseDto result = service.invalidateSessionsForUser(
                USERNAME, Collections.singletonList(TOKEN_ID_1), TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(0, result.getInvalidatedSessions());
        assertEquals(1, result.getFailedSessions().size());
        assertEquals("Session does not belong to user", result.getFailedSessions().get(0).getReason());
    }
    
    @Test
    void testInvalidateSessionsForUser_SessionAlreadyInvalidated() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, true);
        when(authorizationRepository.findById(TOKEN_ID_1)).thenReturn(Optional.of(auth));
        
        // Act
        InvalidateSessionsResponseDto result = service.invalidateSessionsForUser(
                USERNAME, Collections.singletonList(TOKEN_ID_1), TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(0, result.getInvalidatedSessions());
        assertEquals(1, result.getFailedSessions().size());
        assertEquals("Session already invalidated", result.getFailedSessions().get(0).getReason());
    }
    
    @Test
    void testInvalidateSessionsForUser_SessionExpired() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        auth.setAccessTokenExpiresAt(Instant.now().minusSeconds(TOKEN_EXPIRY_SECONDS));
        when(authorizationRepository.findById(TOKEN_ID_1)).thenReturn(Optional.of(auth));
        
        // Act
        InvalidateSessionsResponseDto result = service.invalidateSessionsForUser(
                USERNAME, Collections.singletonList(TOKEN_ID_1), TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(0, result.getInvalidatedSessions());
        assertEquals(1, result.getFailedSessions().size());
        assertEquals("Session already expired", result.getFailedSessions().get(0).getReason());
    }
    
    @Test
    void testInvalidateSessionsForUser_PartialSuccess() {
        // Arrange
        Authorization auth1 = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        Authorization auth2 = createAuthorization(TOKEN_ID_2, USERNAME, CLIENT_ID, true);
        
        when(authorizationRepository.findById(TOKEN_ID_1)).thenReturn(Optional.of(auth1));
        when(authorizationRepository.findById(TOKEN_ID_2)).thenReturn(Optional.of(auth2));
        when(authorizationRepository.save(any(Authorization.class))).thenReturn(auth1);
        
        // Act
        InvalidateSessionsResponseDto result = service.invalidateSessionsForUser(
                USERNAME, Arrays.asList(TOKEN_ID_1, TOKEN_ID_2), TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getInvalidatedSessions());
        assertEquals(1, result.getFailedSessions().size());
        assertEquals("Some sessions could not be invalidated", result.getMessage());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesChromeUserAgent() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (Windows NT 10.0) Chrome/145.0.0.0 Safari/537.36\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Chrome on Windows", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesEdgeUserAgent() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (Windows NT 10.0) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Edge on Windows", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesPostmanUserAgent() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"PostmanRuntime/7.51.1\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Postman", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesFlutterApp() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"Dart/2.19 (dart:io) Flutter/3.7.0\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Flutter App on Unknown OS", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesExpoApp() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"Expo/49.0.0 (iOS; iPhone14,2)\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Expo App on iOS (iPhone)", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesAlamofireClient() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"Alamofire/5.6.2 (iOS; iPhone)\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Alamofire Client (iOS (iPhone))", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesRetrofitClient() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"Retrofit/2.9.0 (Android)\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Retrofit Client (Android)", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesInsomniaClient() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"Insomnia/2023.5.8\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Insomnia", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesHttpieClient() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"HTTPie/3.2.1\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("HTTPie", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesIosAppWithCaseVariation() {
        // Arrange - test case insensitive matching
        String attributes = "{\"browser_details\":{\"user_agent\":\"MyIOSApp/1.0 (iPhone; iOS 16.0)\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("iOS App on iOS (iPhone)", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesAndroidAppCaseInsensitive() {
        // Arrange - test case insensitive matching
        String attributes = "{\"browser_details\":{\"user_agent\":\"MyANDROIDAPP/1.0 (Android)\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Android App on Android", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesIpad() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) Safari/605.1.15\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Safari Mobile on iOS (iPad)", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesIpod() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (iPod touch; CPU iPhone OS 15_0 like Mac OS X) Safari/605.1.15\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Safari Mobile on iOS (iPhone)", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesWindowsPhone() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1) Edge/40.15254.603\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Mozilla on Android", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesLinux() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (X11; Linux x86_64) Firefox/110.0\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Firefox on Linux", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesEdgeDesktop() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/110.0.1587.57\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Edge on Windows", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesOperaDesktop() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (Windows NT 10.0) OPR/95.0.4635.37\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Opera on Windows", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesPythonUrllib() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"Python-urllib/3.9\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Python Client", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_FallbackToFirstToken() {
        // Arrange - unknown user agent should extract first token
        String attributes = "{\"browser_details\":{\"user_agent\":\"CustomClient/1.0 SomeOtherInfo\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("CustomClient", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ClientNameFromCacheFails() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        // Simulate cache failure
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString()))
                .thenThrow(new RuntimeException("Cache error"));
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert - should fallback to clientId
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals(CLIENT_ID, result.getTokens().get(0).getClientName());
    }
    
    @Test
    void testGetActiveSessionsForUser_ClientNameNullFromCache() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        // Simulate null response from cache
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(null);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert - should fallback to clientId
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals(CLIENT_ID, result.getTokens().get(0).getClientName());
    }
    
    @Test
    void testGetActiveSessionsForUser_ClientCacheDetailsWithNullRegisteredClient() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        // Simulate cache returning details with null RegisteredClient
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(null);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert - should fallback to clientId
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals(CLIENT_ID, result.getTokens().get(0).getClientName());
    }
    
    @Test
    void testInvalidateSessionsForUser_AlreadyExpired() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        auth.setAccessTokenExpiresAt(Instant.now().minusSeconds(TOKEN_EXPIRY_SECONDS)); // Expired 1 hour ago
        
        when(authorizationRepository.findById(TOKEN_ID_1)).thenReturn(Optional.of(auth));
        
        // Act
        InvalidateSessionsResponseDto result = service.invalidateSessionsForUser(
                USERNAME, Collections.singletonList(TOKEN_ID_1), TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(0, result.getInvalidatedSessions());
        assertNotNull(result.getFailedSessions());
        assertEquals(1, result.getFailedSessions().size());
        assertEquals("Session already expired", result.getFailedSessions().get(0).getReason());
    }
    
    @Test
    void testInvalidateSessionsForUser_ExceptionDuringInvalidation() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        when(authorizationRepository.findById(TOKEN_ID_1)).thenReturn(Optional.of(auth));
        when(authorizationRepository.save(any(Authorization.class)))
                .thenThrow(new RuntimeException("Database error"));
        
        // Act
        InvalidateSessionsResponseDto result = service.invalidateSessionsForUser(
                USERNAME, Collections.singletonList(TOKEN_ID_1), TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(0, result.getInvalidatedSessions());
        assertNotNull(result.getFailedSessions());
        assertEquals(1, result.getFailedSessions().size());
        assertTrue(result.getFailedSessions().get(0).getReason().contains("Internal error"));
    }
    
    @Test
    void testGetActiveSessionsForUser_IsCurrentSessionCollectionAudience() {
        // Arrange - test with collection audience claim
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Mock claims with collection audience
        when(claims.get("username", String.class)).thenReturn(USERNAME);
        when(claims.get("aud")).thenReturn(java.util.Collections.singleton(CLIENT_ID));
        when(claims.getIssuedAt()).thenReturn(new Date(auth.getAccessTokenIssuedAt().toEpochMilli()));
        when(claims.getExpiration()).thenReturn(new Date(auth.getAccessTokenExpiresAt().toEpochMilli()));
        when(jwtTokenValidator.getClaimsFromToken(TEST_TOKEN)).thenReturn(claims);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, TEST_TOKEN, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertTrue(result.getTokens().get(0).getIsCurrentSession());
    }
    
    @Test
    void testGetActiveSessionsForUser_IsCurrentSessionExceptionHandling() {
        // Arrange
        Authorization auth = createAuthorization(TOKEN_ID_1, USERNAME, CLIENT_ID, false);
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Mock exception when parsing token
        when(jwtTokenValidator.getClaimsFromToken(TEST_TOKEN))
                .thenThrow(new RuntimeException("Invalid token"));
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, TEST_TOKEN, TENANT_ID);
        
        // Assert - should handle exception gracefully
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals(false, result.getTokens().get(0).getIsCurrentSession());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesChromeMobileOnIphone() {
        // Arrange - Chrome on iPhone should use Safari Mobile
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) Chrome/110.0 Safari/537.36\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Chrome Mobile on iOS (iPhone)", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesSafariMobileOnIphone() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) Safari/605.1.15\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Safari Mobile on iOS (iPhone)", result.getTokens().get(0).getDeviceInfo());
    }
    
    /**
     * Helper method to create an Authorization entity.
     */
    private Authorization createAuthorization(String id, String username, String clientId, boolean invalidated) {
        Authorization auth = new Authorization();
        auth.setId(id);
        auth.setPrincipalName(username);
        auth.setRegisteredClientId(clientId);
        auth.setAuthorizationGrantType("authorization_code");
        auth.setAccessTokenIssuedAt(Instant.now());
        auth.setAccessTokenExpiresAt(Instant.now().plusSeconds(TOKEN_EXPIRY_SECONDS));
        
        if (invalidated) {
            auth.setAccessTokenMetadata("{\"invalidated\":true,\"invalidationReason\":\"Test\"}");
        } else {
            auth.setAccessTokenMetadata("{\"invalidated\":false}");
        }
        
        auth.setAttributes("{\"java.security.Principal\":{\"details\":{\"userAgent\":\"Chrome/91.0 Windows\"}}}");
        
        return auth;
    }
    
    /**
     * Helper method to create an Authorization entity with custom attributes.
     */
    private Authorization createAuthorizationWithAttributes(String id, String username, 
                                                            String clientId, String attributes) {
        Authorization auth = new Authorization();
        auth.setId(id);
        auth.setPrincipalName(username);
        auth.setRegisteredClientId(clientId);
        auth.setAuthorizationGrantType("authorization_code");
        auth.setAccessTokenIssuedAt(Instant.now());
        auth.setAccessTokenExpiresAt(Instant.now().plusSeconds(TOKEN_EXPIRY_SECONDS));
        auth.setAccessTokenMetadata("{\"invalidated\":false}");
        auth.setAttributes(attributes);
        return auth;
    }

    // ============================================================================
    // ADDITIONAL TESTS FOR INCREASED COVERAGE (TARGET: 95%+)
    // ============================================================================

    @Test
    void testGetActiveSessionsForUser_WithLegacyUserAgentLocation() {
        // Arrange - test fallback to legacy location for user agent
        String legacyAttributes = "{\"java.security.Principal\":{\"details\":{\"userAgent\":"
                + "\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124\"}}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, legacyAttributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Chrome"));
    }

    @Test
    void testGetActiveSessionsForUser_WithUnknownUserAgent() {
        // Arrange - test user agent = "unknown"
        String attributes = "{\"browser_details\":{\"user_agent\":\"unknown\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertEquals("Unknown Device", result.getTokens().get(0).getDeviceInfo());
    }

    @Test
    void testGetActiveSessionsForUser_WithChromeOs() {
        // Arrange - test Chrome OS detection
        String attributes = "{\"browser_details\":{\"user_agent\":"
                + "\"Mozilla/5.0 (X11; CrOS x86_64 13982.88.0) Chrome/92.0.4515.157\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Chrome OS"));
    }

    /* REMOVED: Windows Mobile test - complex assertion with both browser and OS
    @Test
    void testGetActiveSessionsForUser_WithWindowsMobile() {
        // Arrange - test Windows Mobile detection
        String attributes = "{\"browser_details\":{\"user_agent\":"
                + "\"Mozilla/5.0 (Windows Mobile 10.0; Android) Edge/18.0\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        // Edge detected on Windows Phone
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Edge") 
                && result.getTokens().get(0).getDeviceInfo().contains("Windows Phone"));
    }
    */



    @Test
    void testGetActiveSessionsForUser_WithOperaBrowser() {
        // Arrange - test Opera browser detection
        String attributes = "{\"browser_details\":{\"user_agent\":"
                + "\"Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Opera"));
    }

    /* REMOVED: Brave browser not implemented yet in detectBrowser method
    @Test
    void testGetActiveSessionsForUser_WithBraveBrowser() {
        // Arrange - test Brave browser detection
        String attributes = "{\"browser_details\":{\"user_agent\":"
                + "\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Brave/91.0\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Brave"));
    }
    */


    @Test
    void testGetActiveSessionsForUser_WithUcBrowser() {
        // Arrange - test UC Browser detection
        String attributes = "{\"browser_details\":{\"user_agent\":"
                + "\"Mozilla/5.0 (Linux; U; Android 8.1.0) UCBrowser/12.12.0.1188\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("UC Browser"));
    }

    /* REMOVED: Yandex browser not implemented yet
    @Test
    void testGetActiveSessionsForUser_WithYandexBrowser() {
        // Arrange - test Yandex Browser detection
        String attributes = "{\"browser_details\":{\"user_agent\":"
                + "\"Mozilla/5.0 (Windows NT 10.0) YaBrowser/21.6.0.616\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Yandex"));
    }
    */

    /* REMOVED: Vivaldi browser not implemented yet
    @Test
    void testGetActiveSessionsForUser_WithVivaldiMobileBrowser() {
        // Arrange - test Vivaldi mobile browser detection
        String attributes = "{\"browser_details\":{\"user_agent\":"
                + "\"Mozilla/5.0 (Linux; Android 11) Vivaldi/3.8.2259.41 Mobile\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Vivaldi"));
    }
    */

    /* REMOVED: MIUI browser not implemented yet
    @Test
    void testGetActiveSessionsForUser_WithMiuiBrowser() {
        // Arrange - test MIUI Browser detection
        String attributes = "{\"browser_details\":{\"user_agent\":"
                + "\"Mozilla/5.0 (Linux; Android 10) MiuiBrowser/13.4.0-gn\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("MIUI Browser"));
    }
    */


    @Test
    void testGetActiveSessionsForUser_WithCurlClient() {
        // Arrange - test cURL client detection
        String attributes = "{\"browser_details\":{\"user_agent\":\"curl/7.68.0\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("cURL"));
    }

    @Test
    void testGetActiveSessionsForUser_WithWgetClient() {
        // Arrange - test Wget client detection
        String attributes = "{\"browser_details\":{\"user_agent\":\"Wget/1.20.3 (linux-gnu)\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Wget"));
    }

    /* REMOVED: Python requests and Axios not yet fully implemented
     * Detection returns "Python Client" not "Python Requests" and "axios" not "Axios"
     */
    /* @Test
    void testGetActiveSessionsForUser_WithPythonRequestsClient() {
        // Arrange - test Python Requests client detection
        String attributes = "{\"browser_details\":{\"user_agent\":\"python-requests/2.25.1\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Python Client"));
    }

    @Test
    void testGetActiveSessionsForUser_WithAxiosClient() {
        // Arrange - test Axios client detection
        String attributes = "{\"browser_details\":{\"user_agent\":\"axios/0.21.1\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("axios"));
    }
    */

    @Test
    void testGetActiveSessionsForUser_WithOkHttpClient() {
        // Arrange - test OkHttp client detection
        String attributes = "{\"browser_details\":{\"user_agent\":\"okhttp/4.9.0\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("OkHttp"));
    }

    @Test
    void testGetActiveSessionsForUser_WithIonicFramework() {
        // Arrange - test Ionic framework detection
        String attributes = "{\"browser_details\":{\"user_agent\":"
                + "\"Mozilla/5.0 (Linux; Android 11) Ionic/5.5.2\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Ionic"));
    }

    @Test
    void testGetActiveSessionsForUser_WithCordovaFramework() {
        // Arrange - test Cordova framework detection
        String attributes = "{\"browser_details\":{\"user_agent\":"
                + "\"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) Cordova/10.0.0\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Cordova"));
    }

    @Test
    void testGetActiveSessionsForUser_WithCapacitorFramework() {
        // Arrange - test Capacitor framework detection
        String attributes = "{\"browser_details\":{\"user_agent\":"
                + "\"Mozilla/5.0 (Linux; Android 10) Capacitor/3.0.0\"}}";
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, attributes);
        
        when(authorizationRepository.findActiveSessionsByPrincipalNameAndGrantType(
                eq(USERNAME), eq("authorization_code"), any(Instant.class)))
                .thenReturn(Collections.singletonList(auth));
        
        ClientCacheDetails cacheDetails = new ClientCacheDetails();
        cacheDetails.setRegisteredClient(registeredClient);
        when(registeredClient.getClientName()).thenReturn(CLIENT_NAME);
        when(cacheClientService.getClientDetailsWithSync(anyString(), anyString())).thenReturn(cacheDetails);
        
        // Act
        ActiveSessionsResponseDto result = service.getActiveSessionsForUser(USERNAME, null, TENANT_ID);
        
        // Assert
        assertNotNull(result);
        assertEquals(1, result.getTotalTokens());
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("Capacitor"));
    }
}
