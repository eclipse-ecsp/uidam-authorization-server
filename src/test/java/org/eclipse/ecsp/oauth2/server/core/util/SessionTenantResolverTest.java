/********************************************************************************
 * Copyright (c) 2023 - 2024 Harman International
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

package org.eclipse.ecsp.oauth2.server.core.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.sql.multitenancy.TenantContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class SessionTenantResolverTest {

    private static final Integer INVALID_TENANT_TYPE_VALUE = 123;
    
    private MockedStatic<RequestContextHolder> requestContextHolderMock;
    private ServletRequestAttributes mockRequestAttributes;
    private HttpServletRequest mockRequest;
    private HttpSession mockSession;

    @BeforeEach
    void setUp() {
        // Clear any existing tenant context
        TenantContext.clear();
        
        // Setup mocks
        requestContextHolderMock = Mockito.mockStatic(RequestContextHolder.class);
        mockRequestAttributes = mock(ServletRequestAttributes.class);
        mockRequest = mock(HttpServletRequest.class);
        mockSession = mock(HttpSession.class);
        
        // Configure mock chain
        when(mockRequestAttributes.getRequest()).thenReturn(mockRequest);
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
        if (requestContextHolderMock != null) {
            requestContextHolderMock.close();
        }
    }

    @Test
    void getCurrentTenant_shouldReturnTenantFromThreadLocal_whenThreadLocalHasTenant() {
        // Given
        TenantContext.setCurrentTenant("test-tenant");
        
        // When
        String result = SessionTenantResolver.getCurrentTenant();
        
        // Then
        assertEquals("test-tenant", result);
        // Should not try to access session when ThreadLocal has value
        requestContextHolderMock.verifyNoInteractions();
    }

    @Test
    void getCurrentTenant_shouldReturnTenantFromSession_whenThreadLocalEmpty() {
        // Given
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("RESOLVED_TENANT_ID")).thenReturn("session-tenant");
        
        // When
        String result = SessionTenantResolver.getCurrentTenant();
        
        // Then
        assertEquals("session-tenant", result);
        assertEquals("session-tenant", TenantContext.getCurrentTenant()); // Should be set in ThreadLocal
        verify(mockRequest, atLeastOnce()).getSession(false);
        verify(mockSession).getAttribute("RESOLVED_TENANT_ID");
    }

    @Test
    void getCurrentTenant_shouldReturnNull_whenNoRequestContext() {
        // Given
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenThrow(new IllegalStateException("No request context"));
        
        // When
        String result = SessionTenantResolver.getCurrentTenant();
        
        // Then
        assertNull(result);
    }

    @Test
    void getCurrentTenant_shouldReturnNull_whenNoSession() {
        // Given
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(false)).thenReturn(null);
        
        // When
        String result = SessionTenantResolver.getCurrentTenant();
        
        // Then
        assertNull(result);
        verify(mockRequest).getSession(false);
    }

    @Test
    void getCurrentTenant_shouldReturnNull_whenSessionHasNoTenant() {
        // Given
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("RESOLVED_TENANT_ID")).thenReturn(null);
        
        // When
        String result = SessionTenantResolver.getCurrentTenant();
        
        // Then
        assertNull(result);
        verify(mockSession).getAttribute("RESOLVED_TENANT_ID");
    }

    @Test
    void setCurrentTenant_shouldSetInBothThreadLocalAndSession() {
        // Given
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(true)).thenReturn(mockSession);
        
        // When
        SessionTenantResolver.setCurrentTenant("new-tenant");
        
        // Then
        assertEquals("new-tenant", TenantContext.getCurrentTenant());
        verify(mockRequest).getSession(true);
        verify(mockSession).setAttribute("RESOLVED_TENANT_ID", "new-tenant");
    }

    @Test
    void setCurrentTenant_shouldThrowExceptionForEmptyTenant() {
        // When & Then
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, 
            () -> SessionTenantResolver.setCurrentTenant(""));
        
        assertEquals("Tenant ID cannot be null or empty", exception.getMessage());
        assertFalse(TenantContext.hasTenant());
    }

    @Test
    void setCurrentTenant_shouldThrowExceptionForNullTenant() {
        // When & Then
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, 
            () -> SessionTenantResolver.setCurrentTenant(null));
        
        assertEquals("Tenant ID cannot be null or empty", exception.getMessage());
        assertFalse(TenantContext.hasTenant());
    }

    @Test
    void setCurrentTenant_shouldSetInThreadLocalOnly_whenNoRequestContext() {
        // Given
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenThrow(new IllegalStateException("No request context"));
        
        // When
        SessionTenantResolver.setCurrentTenant("tenant-no-session");
        
        // Then
        assertEquals("tenant-no-session", TenantContext.getCurrentTenant());
        // Should still set in ThreadLocal even if session fails
    }

    @Test
    void clearTenant_shouldClearBothThreadLocalAndSession() {
        // Given
        TenantContext.setCurrentTenant("tenant-to-clear");
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        
        // When
        SessionTenantResolver.clearTenant();
        
        // Then
        assertFalse(TenantContext.hasTenant());
        verify(mockRequest, atLeastOnce()).getSession(false);
        verify(mockSession).removeAttribute("RESOLVED_TENANT_ID");
    }

    @Test
    void clearTenant_shouldClearThreadLocalOnly_whenNoSession() {
        // Given
        TenantContext.setCurrentTenant("tenant-to-clear");
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(false)).thenReturn(null);
        
        // When
        SessionTenantResolver.clearTenant();
        
        // Then
        assertFalse(TenantContext.hasTenant());
        verify(mockRequest).getSession(false);
        verifyNoInteractions(mockSession);
    }

    @Test
    void clearTenant_shouldClearThreadLocalOnly_whenNoRequestContext() {
        // Given
        TenantContext.setCurrentTenant("tenant-to-clear");
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenThrow(new IllegalStateException("No request context"));
        
        // When
        SessionTenantResolver.clearTenant();
        
        // Then
        assertFalse(TenantContext.hasTenant());
        // Should still clear ThreadLocal even if session clearing fails
    }

    @Test
    void getCurrentTenant_shouldHandleSessionWithEmptyStringAttribute() {
        // Given
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("RESOLVED_TENANT_ID")).thenReturn("");
        
        // When
        String result = SessionTenantResolver.getCurrentTenant();
        
        // Then
        assertNull(result);
        verify(mockSession).getAttribute("RESOLVED_TENANT_ID");
    }

    @Test
    void getCurrentTenant_shouldHandleSessionWithWhitespaceAttribute() {
        // Given
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("RESOLVED_TENANT_ID")).thenReturn("   ");
        
        // When
        String result = SessionTenantResolver.getCurrentTenant();
        
        // Then
        assertNull(result);
        verify(mockSession).getAttribute("RESOLVED_TENANT_ID");
    }

    @Test
    void getCurrentTenant_shouldHandleClassCastException() {
        // Given
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getAttribute("RESOLVED_TENANT_ID")).thenReturn(INVALID_TENANT_TYPE_VALUE); // Wrong type
        
        // When
        String result = SessionTenantResolver.getCurrentTenant();
        
        // Then
        assertNull(result);
        verify(mockSession).getAttribute("RESOLVED_TENANT_ID");
    }

    @Test
    void setCurrentTenant_shouldHandleSessionCreationError() {
        // Given
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(true)).thenThrow(new IllegalArgumentException("Session error"));
        
        // When & Then - Should not throw exception, just log warning
        SessionTenantResolver.setCurrentTenant("test-tenant");
        
        // Should still set in ThreadLocal
        assertEquals("test-tenant", TenantContext.getCurrentTenant());
    }

    @Test
    void clearTenant_shouldHandleSessionArgumentException() {
        // Given
        TenantContext.setCurrentTenant("tenant-to-clear");
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(false)).thenThrow(new IllegalArgumentException("Session error"));
        
        // When
        SessionTenantResolver.clearTenant();
        
        // Then
        assertFalse(TenantContext.hasTenant());
    }

    @Test
    void updateThreadLocalSafely_shouldHandleInvalidTenant() {
        // Given
        requestContextHolderMock.when(RequestContextHolder::currentRequestAttributes)
            .thenReturn(mockRequestAttributes);
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        // Return invalid-tenant from session
        when(mockSession.getAttribute("RESOLVED_TENANT_ID")).thenReturn("invalid-tenant");
        
        // Mock TenantContext to throw exception for invalid tenant when setting
        try (var mockStatic = Mockito.mockStatic(TenantContext.class)) {
            mockStatic.when(TenantContext::getCurrentTenant).thenReturn(null);
            mockStatic.when(() -> TenantContext.setCurrentTenant("invalid-tenant"))
                .thenThrow(new IllegalArgumentException("Invalid tenant"));
            
            // When
            String result = SessionTenantResolver.getCurrentTenant();
            
            // Then - Should still return the value from session even if ThreadLocal update fails
            assertEquals("invalid-tenant", result);
            
            // Verify that setCurrentTenant was called (and failed silently)
            mockStatic.verify(() -> TenantContext.setCurrentTenant("invalid-tenant"));
        }
    }
}
