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
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UserProperties;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.getUser;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_USER_NAME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the CustomUserPwdAuthenticationProvider.
 */
@ExtendWith(MockitoExtension.class)
class CustomUserPwdAuthenticationProviderTest {

    @Mock
    private UserManagementClient userManagementClient;
    
    @Mock
    private TenantConfigurationService tenantConfigurationService;
    
    @Mock
    private HttpServletRequest request;
    
    @Mock 
    private HttpSession session;
    
    private CustomUserPwdAuthenticationProvider customUserPwdAuthenticationProvider;

    @BeforeEach
    void setUp() {
        customUserPwdAuthenticationProvider = new CustomUserPwdAuthenticationProvider(
            userManagementClient, tenantConfigurationService, request);
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

}