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

package org.eclipse.ecsp.oauth2.server.core.authentication.providers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.audit.context.ActorContext;
import org.eclipse.ecsp.audit.context.RequestContext;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.audit.enums.AuditEventType;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UserProperties;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.metrics.MetricType;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_ATTEMPT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SESSION_USER_RESPONSE_CAPTCHA_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.USER_CAPTCHA_REQUIRED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.USER_ENFORCE_AFTER_NO_OF_FAILURES;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.getUser;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_USER_NAME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the CustomUserPwdAuthenticationProvider.
 */
@ExtendWith(MockitoExtension.class)
class CustomUserPwdAuthenticationProviderTest {

    private static final int MAX_ATTEMPTS_THREE = 3;
    private static final int MAX_ATTEMPTS_FIVE = 5;
    private static final int FAILURE_ATTEMPTS_TWO = 2;
    private static final int FAILURE_ATTEMPTS_THREE = 3;

    @Mock
    private UserManagementClient userManagementClient;
    
    @Mock
    private TenantConfigurationService tenantConfigurationService;
    
    @Mock
    private HttpServletRequest request;
    
    @Mock 
    private HttpSession session;
    
    @Mock
    private AuthorizationMetricsService authorizationMetricsService;
    
    @Mock
    private AuditLogger auditLogger;

    private CustomUserPwdAuthenticationProvider customUserPwdAuthenticationProvider;

    @BeforeEach
    void setUp() {
        customUserPwdAuthenticationProvider = new CustomUserPwdAuthenticationProvider(
            userManagementClient, tenantConfigurationService, request, authorizationMetricsService, auditLogger);
    }

    /**
     * This method tests the scenario where the authentication attempt is successful.
     * It sets up the necessary parameters and then calls the authenticate method.
     * The test asserts that the returned Authentication object is not null and that its properties match the expected
     * values.
     */
    @Test
    void testAuthenticateSuccess() {
        // Setup tenant properties mock
        TenantProperties tenantProperties = mock(TenantProperties.class);
        UserProperties userProperties = mock(UserProperties.class);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getUser()).thenReturn(userProperties);
        when(userProperties.getMaxAllowedLoginAttempts()).thenReturn(1);
        
        // Setup user management client mock
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());
        
        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
            TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        CustomUserPwdAuthenticationToken authenticationToken =
            (CustomUserPwdAuthenticationToken) customUserPwdAuthenticationProvider.authenticate(authentication);
        assertNotNull(authenticationToken);
        assertEquals(authentication.getPrincipal(), authenticationToken.getPrincipal());
        assertEquals(authentication.getCredentials(), authenticationToken.getCredentials());
        assertEquals(authentication.getAccountName(), authenticationToken.getAccountName());
    }

    /**
     * This method tests the scenario where the authentication attempt fails.
     * It sets up the necessary parameters and then calls the authenticate method.
     * The test expects a BadCredentialsException to be thrown.
     */
    @Test
    void testAuthenticateFail() {
        // Setup tenant properties mock
        TenantProperties tenantProperties = mock(TenantProperties.class);
        UserProperties userProperties = mock(UserProperties.class);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getUser()).thenReturn(userProperties);
        when(userProperties.getMaxAllowedLoginAttempts()).thenReturn(1);
        
        // Setup session mock for failure case (needed for setRecaptchaSession)
        when(request.getSession()).thenReturn(session);
        
        // Setup user with wrong password
        UserDetailsResponse userDetailsResponse = getUser();
        userDetailsResponse.setPassword(TEST_PASSWORD);
        doReturn(userDetailsResponse).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());
        
        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
            TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        assertThrows(BadCredentialsException.class,
                () -> customUserPwdAuthenticationProvider.authenticate(authentication));
    }

    /**
     * This method tests the scenario where different tenant configurations are used.
     */
    @Test
    void testAuthenticateWithDifferentTenantConfigurations() {
        // Setup tenant properties mock with different max attempts
        TenantProperties tenantProperties = mock(TenantProperties.class);
        UserProperties userProperties = mock(UserProperties.class);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getUser()).thenReturn(userProperties);
        final int maxLoginAttempts = 5; // Different from default
        when(userProperties.getMaxAllowedLoginAttempts()).thenReturn(maxLoginAttempts);
        
        // Setup user management client mock
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());
        
        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
            TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        CustomUserPwdAuthenticationToken authenticationToken =
            (CustomUserPwdAuthenticationToken) customUserPwdAuthenticationProvider.authenticate(authentication);
        assertNotNull(authenticationToken);
        assertEquals(authentication.getPrincipal(), authenticationToken.getPrincipal());
        assertEquals(authentication.getCredentials(), authenticationToken.getCredentials());
        assertEquals(authentication.getAccountName(), authenticationToken.getAccountName());
    }

    /**
     * This method tests the supports method of the CustomUserPwdAuthenticationProvider.
     * It asserts that the method returns true for CustomUserPwdAuthenticationToken and false for other types of
     * Authentication.
     */
    @Test
    void testSupports() {
        assertTrue(customUserPwdAuthenticationProvider.supports(CustomUserPwdAuthenticationToken.class));
        assertFalse(customUserPwdAuthenticationProvider.supports(UsernamePasswordAuthenticationToken.class));
        assertFalse(
            customUserPwdAuthenticationProvider.supports(OAuth2AuthorizationCodeRequestAuthenticationToken.class));
    }

    /**
     * This method tests that the AUTH_SUCCESS_PASSWORD audit event is logged correctly
     * when authentication is successful. It verifies:
     * 1) AuditLogger is called exactly once
     * 2) Event type is "AUTH_SUCCESS_PASSWORD"
     * 3) Component name is "UIDAM_AUTHORIZATION_SERVER"
     * 4) Result is SUCCESS
     * 5) Message indicates successful authentication
     * 6) Actor context contains user information
     * 7) Request context is populated
     */
    @Test
    void testAuthenticateSuccess_AuditsAuthSuccessPassword() {
        // Setup tenant properties mock
        TenantProperties tenantProperties = mock(TenantProperties.class);
        UserProperties userProperties = mock(UserProperties.class);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getUser()).thenReturn(userProperties);
        when(userProperties.getMaxAllowedLoginAttempts()).thenReturn(1);
        
        // Setup user management client mock
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());
        
        // Perform authentication
        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
            TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        CustomUserPwdAuthenticationToken authenticationToken =
            (CustomUserPwdAuthenticationToken) customUserPwdAuthenticationProvider.authenticate(authentication);
        
        // Verify authentication succeeded
        assertNotNull(authenticationToken);
        
        // Verify audit logger was called with correct parameters
        ArgumentCaptor<String> eventTypeCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> componentCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<AuditEventResult> resultCaptor = ArgumentCaptor.forClass(AuditEventResult.class);
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<ActorContext> actorContextCaptor = ArgumentCaptor.forClass(ActorContext.class);
        ArgumentCaptor<RequestContext> requestContextCaptor = ArgumentCaptor.forClass(RequestContext.class);
        
        verify(auditLogger, times(1)).log(
            eventTypeCaptor.capture(),
            componentCaptor.capture(),
            resultCaptor.capture(),
            messageCaptor.capture(),
            actorContextCaptor.capture(),
            requestContextCaptor.capture()
        );
        
        // Verify captured values
        assertEquals(AuditEventType.AUTH_SUCCESS_PASSWORD.getType(), eventTypeCaptor.getValue(), 
            "Event type should be AUTH_SUCCESS_PASSWORD");
        assertEquals("UIDAM_AUTHORIZATION_SERVER", componentCaptor.getValue(), 
            "Component should be UIDAM_AUTHORIZATION_SERVER");
        assertEquals(AuditEventResult.SUCCESS, resultCaptor.getValue(), 
            "Result should be SUCCESS");
        assertEquals("User authenticated successfully via password", messageCaptor.getValue(), 
            "Message should indicate successful authentication");
        assertNotNull(actorContextCaptor.getValue(), "Actor context should not be null");
        assertNotNull(requestContextCaptor.getValue(), "Request context should not be null");
    }

    /**
     * This method tests that audit logger is NOT called when authentication fails.
     * Only successful authentications should be audited with AUTH_SUCCESS_PASSWORD.
     */
    @Test
    void testAuthenticateFail_NoAuditLogForAuthSuccessPassword() {
        // Setup tenant properties mock
        TenantProperties tenantProperties = mock(TenantProperties.class);
        UserProperties userProperties = mock(UserProperties.class);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getUser()).thenReturn(userProperties);
        when(userProperties.getMaxAllowedLoginAttempts()).thenReturn(1);
        
        // Setup session mock for failure case (needed for setRecaptchaSession)
        when(request.getSession()).thenReturn(session);
        
        // Setup user with wrong password
        UserDetailsResponse userDetailsResponse = getUser();
        userDetailsResponse.setPassword(TEST_PASSWORD);
        doReturn(userDetailsResponse).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());
        
        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
            TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        
        // Verify authentication fails
        assertThrows(BadCredentialsException.class,
                () -> customUserPwdAuthenticationProvider.authenticate(authentication));
        
        // Verify audit logger was NOT called for AUTH_SUCCESS_PASSWORD (since authentication failed)
        verify(auditLogger, never()).log(
            eq(AuditEventType.AUTH_SUCCESS_PASSWORD.getType()),
            anyString(),
            any(AuditEventResult.class),
            anyString(),
            any(ActorContext.class),
            any(RequestContext.class)
        );
    }

    @Test
    void testAuthenticateWithUserNotFoundException() {
        // Setup tenant properties mock
        TenantProperties tenantProperties = mock(TenantProperties.class);
        UserProperties userProperties = mock(UserProperties.class);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getUser()).thenReturn(userProperties);
        when(userProperties.getMaxAllowedLoginAttempts()).thenReturn(MAX_ATTEMPTS_THREE);
        when(tenantProperties.getTenantId()).thenReturn("test-tenant");
        
        // Setup mock to throw OAuth2AuthenticationException with USER_NOT_FOUND error code
        org.springframework.security.oauth2.core.OAuth2Error error = 
            new org.springframework.security.oauth2.core.OAuth2Error("USER_NOT_FOUND", "User not found", null);
        org.springframework.security.oauth2.core.OAuth2AuthenticationException exception = 
            new org.springframework.security.oauth2.core.OAuth2AuthenticationException(error);
        
        when(userManagementClient.getUserDetailsByUsername(anyString(), anyString())).thenThrow(exception);
        
        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(
            TEST_USER_NAME, TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        
        // Verify that OAuth2AuthenticationException is thrown
        assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,
                () -> customUserPwdAuthenticationProvider.authenticate(authentication));
        
        // Verify metrics were incremented for total login attempts
        verify(authorizationMetricsService).incrementMetricsForTenant(eq("test-tenant"), 
            eq(MetricType.TOTAL_LOGIN_ATTEMPTS));
    }

    @Test
    void testAuthenticateWithGenericException() {
        // Setup tenant properties mock
        TenantProperties tenantProperties = mock(TenantProperties.class);
        UserProperties userProperties = mock(UserProperties.class);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getUser()).thenReturn(userProperties);
        when(userProperties.getMaxAllowedLoginAttempts()).thenReturn(MAX_ATTEMPTS_THREE);
        when(tenantProperties.getTenantId()).thenReturn("test-tenant");
        
        // Setup mock to throw OAuth2AuthenticationException with generic error code
        org.springframework.security.oauth2.core.OAuth2Error error = 
            new org.springframework.security.oauth2.core.OAuth2Error("GENERIC_ERROR", "Generic error", null);
        org.springframework.security.oauth2.core.OAuth2AuthenticationException exception = 
            new org.springframework.security.oauth2.core.OAuth2AuthenticationException(error);
        
        when(userManagementClient.getUserDetailsByUsername(anyString(), anyString())).thenThrow(exception);
        
        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(
            TEST_USER_NAME, TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        
        // Verify that OAuth2AuthenticationException is thrown
        assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,
                () -> customUserPwdAuthenticationProvider.authenticate(authentication));
    }

    @Test
    void testAuthenticateFailureWithCaptchaSettings() {
        // Setup tenant properties mock
        TenantProperties tenantProperties = mock(TenantProperties.class);
        UserProperties userProperties = mock(UserProperties.class);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getUser()).thenReturn(userProperties);
        when(userProperties.getMaxAllowedLoginAttempts()).thenReturn(MAX_ATTEMPTS_FIVE);
        when(tenantProperties.getTenantId()).thenReturn("test-tenant");
        
        // Setup session mock
        when(request.getSession()).thenReturn(session);
        when(request.getSession(false)).thenReturn(session);
        
        // Setup user with wrong password and captcha settings
        UserDetailsResponse userDetailsResponse = getUser();
        userDetailsResponse.setPassword("differentPassword");
        userDetailsResponse.setFailureLoginAttempts(FAILURE_ATTEMPTS_TWO);
        userDetailsResponse.getCaptcha().put(USER_CAPTCHA_REQUIRED, true);
        userDetailsResponse.getCaptcha().put(USER_ENFORCE_AFTER_NO_OF_FAILURES, MAX_ATTEMPTS_THREE);
        
        doReturn(userDetailsResponse).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());
        
        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(
            TEST_USER_NAME, "wrongPassword", TEST_ACCOUNT_NAME, null);
        
        // Verify authentication fails
        assertThrows(BadCredentialsException.class,
                () -> customUserPwdAuthenticationProvider.authenticate(authentication));
        
        // Verify session attributes were set for captcha
        verify(session).setAttribute(eq(SESSION_USER_RESPONSE_CAPTCHA_ENABLED), eq(true));
        verify(session).setAttribute(eq(SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES), 
            eq(MAX_ATTEMPTS_THREE));
        verify(session).setAttribute(eq(LOGIN_ATTEMPT), eq(MAX_ATTEMPTS_THREE));
    }

    @Test
    void testAuthenticateFailureNearMaxAttempts() {
        // Setup tenant properties mock
        TenantProperties tenantProperties = mock(TenantProperties.class);
        UserProperties userProperties = mock(UserProperties.class);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getUser()).thenReturn(userProperties);
        when(userProperties.getMaxAllowedLoginAttempts()).thenReturn(MAX_ATTEMPTS_FIVE);
        when(tenantProperties.getTenantId()).thenReturn("test-tenant");
        
        // Setup session mock
        when(request.getSession()).thenReturn(session);
        when(request.getSession(false)).thenReturn(session);
        
        // Setup user with wrong password and 4 previous failures (next will be 5th = max)
        UserDetailsResponse userDetailsResponse = getUser();
        userDetailsResponse.setPassword("differentPassword");
        userDetailsResponse.setFailureLoginAttempts(FAILURE_ATTEMPTS_THREE); // Next attempt will be 4
        userDetailsResponse.getCaptcha().put(USER_CAPTCHA_REQUIRED, false);
        userDetailsResponse.getCaptcha().put(USER_ENFORCE_AFTER_NO_OF_FAILURES, MAX_ATTEMPTS_FIVE);
        
        doReturn(userDetailsResponse).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());
        
        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(
            TEST_USER_NAME, "wrongPassword", TEST_ACCOUNT_NAME, null);
        
        // Verify authentication fails (but not locked yet)
        BadCredentialsException exception = assertThrows(BadCredentialsException.class,
                () -> customUserPwdAuthenticationProvider.authenticate(authentication));
        
        assertEquals("Bad credentials", exception.getMessage());
        
        // Verify failure metrics were incremented
        verify(authorizationMetricsService).incrementMetricsForTenant(eq("test-tenant"), 
            eq(MetricType.FAILURE_LOGIN_WRONG_PASSWORD), eq(MetricType.FAILURE_LOGIN_ATTEMPTS));
    }

    @Test
    void testSupportsCustomUserPwdAuthenticationToken() {
        assertTrue(customUserPwdAuthenticationProvider.supports(CustomUserPwdAuthenticationToken.class));
    }

    @Test
    void testDoesNotSupportOtherAuthenticationTypes() {
        assertFalse(customUserPwdAuthenticationProvider.supports(
            UsernamePasswordAuthenticationToken.class));
        assertFalse(customUserPwdAuthenticationProvider.supports(
            OAuth2AuthorizationCodeRequestAuthenticationToken.class));
    }

}