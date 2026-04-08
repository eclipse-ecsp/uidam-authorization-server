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

package org.eclipse.ecsp.oauth2.server.core.controller;

import io.jsonwebtoken.Claims;
import org.eclipse.ecsp.oauth2.server.core.request.dto.AdminGetActiveSessionsRequestDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.AdminInvalidateSessionsRequestDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.InvalidateSessionsRequestDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.ActiveSessionDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.ActiveSessionsResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.FailedSessionDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.InvalidateSessionsResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.SessionManagementService;
import org.eclipse.ecsp.oauth2.server.core.utils.JwtTokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for SessionManagementController.
 */
@ExtendWith(MockitoExtension.class)
class SessionManagementControllerTest {
    
    @Mock
    private SessionManagementService sessionManagementService;
    
    @Mock
    private JwtTokenValidator jwtTokenValidator;
    
    @InjectMocks
    private SessionManagementController controller;
    
    private static final String TENANT_ID = "test-tenant";
    private static final String USERNAME = "test.user@example.com";
    private static final String TOKEN_ID_1 = "token-id-1";
    private static final String TOKEN_ID_2 = "token-id-2";
    private static final long TOKEN_EXPIRY_SECONDS = 3600L;
    private static final int EXPECTED_TOKEN_COUNT = 2;
    private static final String VALID_TOKEN = "Bearer valid-jwt-token";
    private static final String SELF_MANAGE_SCOPE = "SelfManage";
    private static final String MANAGE_USERS_SCOPE = "ManageUsers";
    
    @BeforeEach
    void setUp() {
        // Mock token introspection (now using introspectToken instead of validateToken)
        lenient().when(jwtTokenValidator.introspectToken(anyString(), eq(SELF_MANAGE_SCOPE))).thenReturn(true);
        lenient().when(jwtTokenValidator.introspectToken(anyString(), eq(MANAGE_USERS_SCOPE))).thenReturn(true);
        
        // Mock claims extraction - use @Mock for Claims
        Claims mockClaims = org.mockito.Mockito.mock(Claims.class);
        lenient().when(mockClaims.get(eq("username"), eq(String.class))).thenReturn(USERNAME);
        lenient().when(jwtTokenValidator.getClaimsFromToken(anyString())).thenReturn(mockClaims);
    }
    
    @Test
    void testGetSelfActiveSessions_Success() {
        // Arrange
        ActiveSessionDto session = ActiveSessionDto.builder()
                .id(TOKEN_ID_1)
                .clientName("Web Portal")
                .accessTokenIssuedAt(Instant.now())
                .accessTokenExpiresAt(Instant.now().plusSeconds(TOKEN_EXPIRY_SECONDS))
                .deviceInfo("Chrome on Windows")
                .isCurrentSession(true)
                .build();
        
        ActiveSessionsResponseDto expectedResponse = ActiveSessionsResponseDto.builder()
                .tokens(Collections.singletonList(session))
                .totalTokens(1)
                .build();
        
        // Now expects the token string to be passed (not null)
        when(sessionManagementService.getActiveSessionsForUser(
                eq(USERNAME), eq("valid-jwt-token"), eq(TENANT_ID)))
                .thenReturn(expectedResponse);
        
        // Act
        ResponseEntity<?> response = controller.getSelfActiveSessions(TENANT_ID, VALID_TOKEN);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(sessionManagementService).getActiveSessionsForUser(USERNAME, "valid-jwt-token", TENANT_ID);
    }
    
    @Test
    void testGetSelfActiveSessions_Error() {
        // Arrange
        when(sessionManagementService.getActiveSessionsForUser(
                anyString(), anyString(), anyString()))
                .thenThrow(new RuntimeException("Database error"));
        
        // Act
        ResponseEntity<?> response = controller.getSelfActiveSessions(TENANT_ID, VALID_TOKEN);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }
    
    @Test
    void testInvalidateSelfSessions_Success() {
        // Arrange
        InvalidateSessionsRequestDto request = InvalidateSessionsRequestDto.builder()
                .tokenIds(Arrays.asList(TOKEN_ID_1, TOKEN_ID_2))
                .build();
        
        InvalidateSessionsResponseDto expectedResponse = InvalidateSessionsResponseDto.builder()
                .invalidatedSessions(EXPECTED_TOKEN_COUNT)
                .failedSessions(null)
                .message("Sessions invalidated successfully")
                .build();
        
        when(sessionManagementService.invalidateSessionsForUser(eq(USERNAME), anyList(), eq(TENANT_ID)))
                .thenReturn(expectedResponse);
        
        // Act
        ResponseEntity<?> response = controller.invalidateSelfSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(sessionManagementService).invalidateSessionsForUser(USERNAME, request.getTokenIds(), TENANT_ID);
    }
    
    @Test
    void testInvalidateSelfSessions_PartialSuccess() {
        // Arrange
        InvalidateSessionsRequestDto request = InvalidateSessionsRequestDto.builder()
                .tokenIds(Arrays.asList(TOKEN_ID_1, TOKEN_ID_2))
                .build();
        
        FailedSessionDto failedSession = FailedSessionDto.builder()
                .tokenId(TOKEN_ID_2)
                .reason("Session not found")
                .build();
        
        InvalidateSessionsResponseDto expectedResponse = InvalidateSessionsResponseDto.builder()
                .invalidatedSessions(1)
                .failedSessions(Collections.singletonList(failedSession))
                .message("Some sessions could not be invalidated")
                .build();
        
        when(sessionManagementService.invalidateSessionsForUser(eq(USERNAME), anyList(), eq(TENANT_ID)))
                .thenReturn(expectedResponse);
        
        // Act
        ResponseEntity<?> response = controller.invalidateSelfSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.MULTI_STATUS, response.getStatusCode());
    }
    
    @Test
    void testInvalidateSelfSessions_Error() {
        // Arrange
        InvalidateSessionsRequestDto request = InvalidateSessionsRequestDto.builder()
                .tokenIds(Collections.singletonList(TOKEN_ID_1))
                .build();
        
        when(sessionManagementService.invalidateSessionsForUser(anyString(), anyList(), anyString()))
                .thenThrow(new RuntimeException("Database error"));
        
        // Act
        ResponseEntity<?> response = controller.invalidateSelfSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }
    
    @Test
    void testGetAdminActiveSessions_Success() {
        // Arrange
        AdminGetActiveSessionsRequestDto request = AdminGetActiveSessionsRequestDto.builder()
                .username(USERNAME)
                .build();
        
        ActiveSessionDto session = ActiveSessionDto.builder()
                .id(TOKEN_ID_1)
                .clientName("Mobile App")
                .accessTokenIssuedAt(Instant.now())
                .accessTokenExpiresAt(Instant.now().plusSeconds(TOKEN_EXPIRY_SECONDS))
                .deviceInfo("Safari on iOS")
                .build();
        
        ActiveSessionsResponseDto expectedResponse = ActiveSessionsResponseDto.builder()
                .tokens(Collections.singletonList(session))
                .totalTokens(1)
                .username(USERNAME)
                .build();
        
        when(sessionManagementService.getActiveSessionsForUser(eq(USERNAME), isNull(), eq(TENANT_ID)))
                .thenReturn(expectedResponse);
        
        // Act
        ResponseEntity<?> response = controller.getAdminActiveSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(sessionManagementService).getActiveSessionsForUser(USERNAME, null, TENANT_ID);
    }
    
    @Test
    void testGetAdminActiveSessions_Error() {
        // Arrange
        AdminGetActiveSessionsRequestDto request = AdminGetActiveSessionsRequestDto.builder()
                .username(USERNAME)
                .build();
        
        when(sessionManagementService.getActiveSessionsForUser(anyString(), isNull(), anyString()))
                .thenThrow(new RuntimeException("Database error"));
        
        // Act
        ResponseEntity<?> response = controller.getAdminActiveSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }
    
    @Test
    void testInvalidateAdminSessions_Success() {
        // Arrange
        AdminInvalidateSessionsRequestDto request = AdminInvalidateSessionsRequestDto.builder()
                .username(USERNAME)
                .tokenIds(Arrays.asList(TOKEN_ID_1, TOKEN_ID_2))
                .build();
        
        InvalidateSessionsResponseDto expectedResponse = InvalidateSessionsResponseDto.builder()
                .invalidatedSessions(EXPECTED_TOKEN_COUNT)
                .failedSessions(null)
                .message("Sessions invalidated successfully")
                .build();
        
        when(sessionManagementService.invalidateSessionsForUser(eq(USERNAME), anyList(), eq(TENANT_ID)))
                .thenReturn(expectedResponse);
        
        // Act
        ResponseEntity<?> response = controller.invalidateAdminSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(sessionManagementService).invalidateSessionsForUser(USERNAME, request.getTokenIds(), TENANT_ID);
    }
    
    @Test
    void testInvalidateAdminSessions_PartialSuccess() {
        // Arrange
        AdminInvalidateSessionsRequestDto request = AdminInvalidateSessionsRequestDto.builder()
                .username(USERNAME)
                .tokenIds(Arrays.asList(TOKEN_ID_1, TOKEN_ID_2))
                .build();
        
        FailedSessionDto failedSession = FailedSessionDto.builder()
                .tokenId(TOKEN_ID_2)
                .reason("Session already expired")
                .build();
        
        InvalidateSessionsResponseDto expectedResponse = InvalidateSessionsResponseDto.builder()
                .invalidatedSessions(1)
                .failedSessions(Collections.singletonList(failedSession))
                .message("Some sessions could not be invalidated")
                .build();
        
        when(sessionManagementService.invalidateSessionsForUser(eq(USERNAME), anyList(), eq(TENANT_ID)))
                .thenReturn(expectedResponse);
        
        // Act
        ResponseEntity<?> response = controller.invalidateAdminSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.MULTI_STATUS, response.getStatusCode());
    }
    
    @Test
    void testInvalidateAdminSessions_Error() {
        // Arrange
        AdminInvalidateSessionsRequestDto request = AdminInvalidateSessionsRequestDto.builder()
                .username(USERNAME)
                .tokenIds(Collections.singletonList(TOKEN_ID_1))
                .build();
        
        when(sessionManagementService.invalidateSessionsForUser(anyString(), anyList(), anyString()))
                .thenThrow(new RuntimeException("Database error"));
        
        // Act
        ResponseEntity<?> response = controller.invalidateAdminSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }
    
    @Test
    void testGetSelfActiveSessions_UnauthorizedInvalidToken() {
        // Arrange
        lenient().when(jwtTokenValidator.introspectToken(anyString(), eq(SELF_MANAGE_SCOPE))).thenReturn(false);
        
        // Act
        ResponseEntity<?> response = controller.getSelfActiveSessions(TENANT_ID, VALID_TOKEN);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }
    
    @Test
    void testInvalidateSelfSessions_UnauthorizedInvalidToken() {
        // Arrange
        lenient().when(jwtTokenValidator.introspectToken(anyString(), eq(SELF_MANAGE_SCOPE))).thenReturn(false);
        
        InvalidateSessionsRequestDto request = InvalidateSessionsRequestDto.builder()
                .tokenIds(Arrays.asList(TOKEN_ID_1))
                .build();
        
        // Act
        ResponseEntity<?> response = controller.invalidateSelfSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }
    
    @Test
    void testGetAdminActiveSessions_UnauthorizedInvalidToken() {
        // Arrange
        lenient().when(jwtTokenValidator.introspectToken(anyString(), eq(MANAGE_USERS_SCOPE))).thenReturn(false);
        
        AdminGetActiveSessionsRequestDto request = AdminGetActiveSessionsRequestDto.builder()
                .username(USERNAME)
                .build();
        
        // Act
        ResponseEntity<?> response = controller.getAdminActiveSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }
    
    @Test
    void testInvalidateAdminSessions_UnauthorizedInvalidToken() {
        // Arrange
        lenient().when(jwtTokenValidator.introspectToken(anyString(), eq(MANAGE_USERS_SCOPE))).thenReturn(false);
        
        AdminInvalidateSessionsRequestDto request = AdminInvalidateSessionsRequestDto.builder()
                .username(USERNAME)
                .tokenIds(Arrays.asList(TOKEN_ID_1))
                .build();
        
        // Act
        ResponseEntity<?> response = controller.invalidateAdminSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }
    
    @Test
    void testInvalidateSelfSessions_PartialSuccessAllFailed() {
        // Arrange
        InvalidateSessionsRequestDto request = InvalidateSessionsRequestDto.builder()
                .tokenIds(Arrays.asList(TOKEN_ID_1, TOKEN_ID_2))
                .build();
        
        FailedSessionDto failedSession1 = FailedSessionDto.builder()
                .tokenId(TOKEN_ID_1)
                .reason("Session not found")
                .build();
        
        FailedSessionDto failedSession2 = FailedSessionDto.builder()
                .tokenId(TOKEN_ID_2)
                .reason("Session already expired")
                .build();
        
        InvalidateSessionsResponseDto expectedResponse = InvalidateSessionsResponseDto.builder()
                .invalidatedSessions(0)
                .failedSessions(Arrays.asList(failedSession1, failedSession2))
                .message("Some sessions could not be invalidated")
                .build();
        
        when(sessionManagementService.invalidateSessionsForUser(eq(USERNAME), anyList(), eq(TENANT_ID)))
                .thenReturn(expectedResponse);
        
        // Act
        ResponseEntity<?> response = controller.invalidateSelfSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }
    
    @Test
    void testInvalidateAdminSessions_PartialSuccessAllFailed() {
        // Arrange
        AdminInvalidateSessionsRequestDto request = AdminInvalidateSessionsRequestDto.builder()
                .username(USERNAME)
                .tokenIds(Arrays.asList(TOKEN_ID_1, TOKEN_ID_2))
                .build();
        
        FailedSessionDto failedSession1 = FailedSessionDto.builder()
                .tokenId(TOKEN_ID_1)
                .reason("Session not found")
                .build();
        
        FailedSessionDto failedSession2 = FailedSessionDto.builder()
                .tokenId(TOKEN_ID_2)
                .reason("Session already expired")
                .build();
        
        InvalidateSessionsResponseDto expectedResponse = InvalidateSessionsResponseDto.builder()
                .invalidatedSessions(0)
                .failedSessions(Arrays.asList(failedSession1, failedSession2))
                .message("Some sessions could not be invalidated")
                .build();
        
        when(sessionManagementService.invalidateSessionsForUser(eq(USERNAME), anyList(), eq(TENANT_ID)))
                .thenReturn(expectedResponse);
        
        // Act
        ResponseEntity<?> response = controller.invalidateAdminSessions(TENANT_ID, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }
    
    @Test
    void testGetSelfActiveSessions_WithNullTenantId() {
        // Arrange - null tenantId should be resolved
        ActiveSessionDto session = ActiveSessionDto.builder()
                .id(TOKEN_ID_1)
                .clientName("Web Portal")
                .accessTokenIssuedAt(Instant.now())
                .accessTokenExpiresAt(Instant.now().plusSeconds(TOKEN_EXPIRY_SECONDS))
                .deviceInfo("Chrome on Windows")
                .isCurrentSession(true)
                .build();
        
        ActiveSessionsResponseDto expectedResponse = ActiveSessionsResponseDto.builder()
                .tokens(Collections.singletonList(session))
                .totalTokens(1)
                .build();
        
        when(sessionManagementService.getActiveSessionsForUser(
                eq(USERNAME), eq("valid-jwt-token"), any()))
                .thenReturn(expectedResponse);
        
        // Act - pass null as tenantId
        ResponseEntity<?> response = controller.getSelfActiveSessions(null, VALID_TOKEN);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }
    
    @Test
    void testInvalidateSelfSessions_WithNullTenantId() {
        // Arrange
        InvalidateSessionsRequestDto request = InvalidateSessionsRequestDto.builder()
                .tokenIds(Arrays.asList(TOKEN_ID_1))
                .build();
        
        InvalidateSessionsResponseDto expectedResponse = InvalidateSessionsResponseDto.builder()
                .invalidatedSessions(1)
                .failedSessions(null)
                .message("Sessions invalidated successfully")
                .build();
        
        when(sessionManagementService.invalidateSessionsForUser(eq(USERNAME), anyList(), any()))
                .thenReturn(expectedResponse);
        
        // Act - pass null as tenantId
        ResponseEntity<?> response = controller.invalidateSelfSessions(null, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }
    
    @Test
    void testGetAdminActiveSessions_WithNullTenantId() {
        // Arrange
        AdminGetActiveSessionsRequestDto request = AdminGetActiveSessionsRequestDto.builder()
                .username(USERNAME)
                .build();
        
        ActiveSessionDto session = ActiveSessionDto.builder()
                .id(TOKEN_ID_1)
                .clientName("Mobile App")
                .accessTokenIssuedAt(Instant.now())
                .accessTokenExpiresAt(Instant.now().plusSeconds(TOKEN_EXPIRY_SECONDS))
                .deviceInfo("Safari on iOS")
                .build();
        
        ActiveSessionsResponseDto expectedResponse = ActiveSessionsResponseDto.builder()
                .tokens(Collections.singletonList(session))
                .totalTokens(1)
                .username(USERNAME)
                .build();
        
        when(sessionManagementService.getActiveSessionsForUser(eq(USERNAME), isNull(), any()))
                .thenReturn(expectedResponse);
        
        // Act - pass null as tenantId
        ResponseEntity<?> response = controller.getAdminActiveSessions(null, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }
    
    @Test
    void testInvalidateAdminSessions_WithNullTenantId() {
        // Arrange
        AdminInvalidateSessionsRequestDto request = AdminInvalidateSessionsRequestDto.builder()
                .username(USERNAME)
                .tokenIds(Arrays.asList(TOKEN_ID_1))
                .build();
        
        InvalidateSessionsResponseDto expectedResponse = InvalidateSessionsResponseDto.builder()
                .invalidatedSessions(1)
                .failedSessions(null)
                .message("Sessions invalidated successfully")
                .build();
        
        when(sessionManagementService.invalidateSessionsForUser(eq(USERNAME), anyList(), any()))
                .thenReturn(expectedResponse);
        
        // Act - pass null as tenantId
        ResponseEntity<?> response = controller.invalidateAdminSessions(null, VALID_TOKEN, request);
        
        // Assert
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }
}
