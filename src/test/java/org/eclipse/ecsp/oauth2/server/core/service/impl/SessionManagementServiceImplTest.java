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
    void testGetActiveSessionsForUser_ParsesFlutterAppUserAgent() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"Dart/2.18 Flutter/3.3.0 (iPhone; iOS 16.0)\"}}";
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
        assertEquals("Flutter App on iOS (iPhone)", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesChromeMobileUserAgent() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (Linux; Android 12) Chrome/108.0.0.0 Mobile Safari/537.36\"}}";
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
        assertEquals("Chrome Mobile on Android", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesSafariMobileUserAgent() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0) Safari/604.1\"}}";
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
    void testGetActiveSessionsForUser_FallsBackToLegacyFormat() {
        // Arrange - old format without browser_details
        String attributes = "{\"java.security.Principal\":{\"details\":{\"userAgent\":\""
                + "Mozilla/5.0 (Windows NT 10.0) Firefox/110.0\"}}}";
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
        assertEquals("Firefox on Windows", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_HandlesUnknownUserAgent() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"UnknownClient/1.0\"}}";
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
        assertTrue(result.getTokens().get(0).getDeviceInfo().contains("UnknownClient"));
    }
    
    @Test
    void testGetActiveSessionsForUser_HandlesEmptyAttributes() {
        // Arrange
        Authorization auth = createAuthorizationWithAttributes(TOKEN_ID_1, USERNAME, CLIENT_ID, "{}");
        
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
    void testGetActiveSessionsForUser_ParsesOkHttpClient() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"okhttp/4.9.0 (Linux; Android 12)\"}}";
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
        assertEquals("OkHttp Client (Android)", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesReactNativeApp() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"ReactNative/0.70.0 (Android 11)\"}}";
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
        assertEquals("React Native App on Android", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesIonicApp() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"Capacitor/4.0.0 (iPhone; iOS 16.0)\"}}";
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
        assertEquals("Ionic/Capacitor App on iOS (iPhone)", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesCordovaApp() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"Apache Cordova/9.0.0 (Android 10)\"}}";
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
        assertEquals("Cordova App on Android", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesNativeAndroidApp() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "MyAndroidApp/1.0 NativeAndroid (Linux; Android 11)\"}}";
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
    void testGetActiveSessionsForUser_ParsesCurlClient() {
        // Arrange
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
        assertEquals("cURL", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesSamsungBrowser() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (Linux; Android 12) SamsungBrowser/16.0 Safari/537.36\"}}";
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
        assertEquals("Samsung Browser on Android", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesUcBrowser() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (Linux; Android 11) UCBrowser/13.4.0 Safari/537.36\"}}";
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
        assertEquals("UC Browser on Android", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesFirefoxMobile() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"Mozilla/5.0 (Android 12) Firefox/110.0\"}}";
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
        assertEquals("Firefox Mobile on Android", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesSafariDesktop() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (Macintosh; Mac OS X 13_0) Safari/605.1.15\"}}";
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
        assertEquals("Safari on macOS", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesInternetExplorer() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0)\"}}";
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
        assertEquals("Internet Explorer on Windows", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesPythonClient() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"python-requests/2.28.0\"}}";
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
    void testGetActiveSessionsForUser_ParsesJavaClient() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\"Apache-HttpClient/4.5.13 (Java/11.0.12)\"}}";
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
        assertEquals("Java Client", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesOperaMobile() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (Linux; Android 12) Opera/75.0 Safari/537.36\"}}";
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
        assertEquals("Opera Mobile on Android", result.getTokens().get(0).getDeviceInfo());
    }
    
    @Test
    void testGetActiveSessionsForUser_ParsesChromeOs() {
        // Arrange
        String attributes = "{\"browser_details\":{\"user_agent\":\""
                + "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) Chrome/145.0.0.0 Safari/537.36\"}}";
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
        assertEquals("Chrome on Chrome OS", result.getTokens().get(0).getDeviceInfo());
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
}
