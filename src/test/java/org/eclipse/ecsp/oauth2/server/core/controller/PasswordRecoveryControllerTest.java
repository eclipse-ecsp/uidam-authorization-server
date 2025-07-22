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

package org.eclipse.ecsp.oauth2.server.core.controller;

import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.UpdatePasswordData;
import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.CaptchaProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.PasswordRecoveryException;
import org.eclipse.ecsp.oauth2.server.core.service.PasswordPolicyService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.service.impl.CaptchaServiceImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.View;

import java.util.Base64;
import java.util.Map;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * This class tests the functionality of the PasswordRecoveryController with multi-tenant support.
 */
@ExtendWith(MockitoExtension.class)
class PasswordRecoveryControllerTest {

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private UserManagementClient userManagementClient;

    @Mock
    private CaptchaServiceImpl captchaServiceImpl;

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @InjectMocks
    private PasswordRecoveryController passwordRecoveryController;

    private MockMvc mockMvc;

    /**
     * This method sets up the test environment before each test.
     * It initializes the MockMvc instance and sets up default tenant context.
     */
    @BeforeEach
    void setup() {
        TenantContext.setCurrentTenant("ecsp"); // Set default tenant for tests
        this.mockMvc = MockMvcBuilders.standaloneSetup(passwordRecoveryController)
            .setViewResolvers((viewName, locale) -> new View() {
                @Override
                public String getContentType() {
                    return "text/html";
                }

                @Override
                public void render(Map<String, ?> model, 
                                   jakarta.servlet.http.HttpServletRequest request,
                                   jakarta.servlet.http.HttpServletResponse response) throws Exception {
                    response.getWriter().write("Mock view: " + viewName);
                }
            })
            .build();
    }

    /**
     * Clean up tenant context after each test to avoid side effects.
     */
    @AfterEach
    void cleanup() {
        TenantContext.clear();
    }

    /**
     * Creates a mock TenantProperties for testing.
     *
     * @return Mock TenantProperties with default values
     */
    private TenantProperties createMockTenantProperties() {
        TenantProperties tenantProperties = new TenantProperties();
        
        CaptchaProperties captchaProperties = new CaptchaProperties();
        captchaProperties.setRecaptchaKeySite("test-site-key");
        tenantProperties.setCaptcha(captchaProperties);
        
        return tenantProperties;
    }

    /**
     * Test the initial password recovery request is successful for the default tenant.
     */
    @Test
    void testForgotPasswordInit() throws Exception {
        // Mock tenant properties
        TenantProperties tenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        
        this.mockMvc.perform(get("/recovery"))
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/forgot-password"))
                .andExpect(model().attributeExists("isCaptchaFieldEnabled"))
                .andExpect(model().attribute("captchaSite", "test-site-key"));
    }

    /**
     * Test the initial password recovery request with a different tenant.
     */
    @Test
    void testForgotPasswordInitMultiTenant() throws Exception {
        // Switch to different tenant
        TenantContext.setCurrentTenant("tenant2");
        
        // Mock tenant properties for tenant2
        TenantProperties tenantProperties = new TenantProperties();
        CaptchaProperties captchaProperties = new CaptchaProperties();
        captchaProperties.setRecaptchaKeySite("tenant2-site-key");
        tenantProperties.setCaptcha(captchaProperties);
        
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        
        this.mockMvc.perform(get("/recovery"))
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/forgot-password"))
                .andExpect(model().attributeExists("isCaptchaFieldEnabled"))
                .andExpect(model().attribute("captchaSite", "tenant2-site-key"));
    }

    /**
     * Test successful password recovery request.
     */
    @Test
    void testForgotPassword() throws Exception {
        this.mockMvc
                .perform(post("/recovery/forgotPassword")
                        .param("username", "username")
                        .param("accountName", "ignite"))
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/email-sent"))
                .andExpect(model().attributeExists("message"));
    }

    /**
     * Test password recovery when user details are not found.
     */
    @Test
    void testForgotPasswordUserDetailsNotFound() throws Exception {
        // Mock tenant properties
        TenantProperties tenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        
        doThrow(new PasswordRecoveryException("User not found")).when(userManagementClient)
                .sendUserResetPasswordNotification("username", "ignite");
        
        this.mockMvc
                .perform(post("/recovery/forgotPassword")
                        .param("username", "username")
                        .param("accountName", "ignite"))
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/forgot-password"))
                .andExpect(model().attributeExists("error"));
    }

    /**
     * Test password recovery with exception.
     */
    @Test
    void testForgotPasswordUserException() throws Exception {
        // Mock tenant properties
        TenantProperties tenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        
        doThrow(new PasswordRecoveryException("Some error")).when(userManagementClient)
                .sendUserResetPasswordNotification("username", "ignite");
        
        this.mockMvc
                .perform(post("/recovery/forgotPassword")
                        .param("username", "username")
                        .param("accountName", "ignite"))
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/forgot-password"))
                .andExpect(model().attributeExists("error"));
    }

    /**
     * Test successful password reset initialization.
     */
    @Test
    void testForgotPasswordResetInit() throws Exception {
        // Mock tenant properties
        TenantProperties tenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        
        String secret = "secret";
        String nonce = "nonce";
        String encodedParams = Base64.getEncoder().encodeToString(("secret=" + secret + "&nonce=" + nonce).getBytes());
        
        this.mockMvc.perform(get("/recovery/reset/" + encodedParams))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/change-password"))
                .andExpect(model().attribute("secret", secret));
    }

    /**
     * Test password reset with invalid secret.
     */
    @Test
    void testForgotPasswordResetInvalidSecret() throws Exception {
        // No tenant properties mocking needed as InvalidSecretException is thrown early
        
        String secret = "";
        String nonce = "nonce";
        String encodedParams = Base64.getEncoder().encodeToString(("secret=" + secret + "&nonce=" + nonce).getBytes());
        
        this.mockMvc.perform(get("/recovery/reset/" + encodedParams))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/invalid-secret-provided"));
    }

    /**
     * Test password reset with invalid secret exception.
     */
    @Test
    void testForgotPasswordResetInvalidSecretException() throws Exception {
        // No tenant properties mocking needed as InvalidSecretException is thrown early
        
        String secret = "";
        String nonce = "nonce";
        String encodedParams = Base64.getEncoder().encodeToString(("secret=" + secret + "&nonce=" + nonce).getBytes());
        
        this.mockMvc.perform(get("/recovery/reset/" + encodedParams + "123"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/invalid-secret-provided"));
    }

    /**
     * Test successful password reset.
     */
    @Test
    void testPasswordResetSuccess() throws Exception {
        // Mock tenant properties
        TenantProperties tenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        
        when(userManagementClient.updateUserPasswordUsingRecoverySecret(UpdatePasswordData.of("secret", "password")))
                .thenReturn("");
        
        this.mockMvc
                .perform(post("/recovery/reset")
                        .param("password", "password")
                        .param("confirmPassword", "password")
                        .param("secret", "secret"))
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/password-changed"))
                .andExpect(model().attributeExists("message"));
    }

    /**
     * Test password reset with password mismatch.
     */
    @Test
    void testPasswordResetPasswordNotMatchedException() throws Exception {
        // Mock tenant properties - needed for captcha display on error
        TenantProperties tenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        
        // Password mismatch doesn't call userManagementClient, so no stubbing needed
        
        this.mockMvc
                .perform(post("/recovery/reset")
                        .param("password", "password")
                        .param("confirmPassword", "ignite")
                        .param("secret", "secret"))
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/change-password"))
                .andExpect(model().attributeExists("error"));
    }

    /**
     * Test password reset with user management client exception.
     */
    @Test
    void testPasswordResetUserMgmtClientException() throws Exception {
        // Mock tenant properties
        TenantProperties tenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        
        when(userManagementClient.updateUserPasswordUsingRecoverySecret(UpdatePasswordData.of("secret", "password")))
                .thenThrow(new RuntimeException("failed to process request"));
        
        this.mockMvc
                .perform(post("/recovery/reset")
                        .param("password", "password")
                        .param("confirmPassword", "password")
                        .param("secret", "secret"))
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/forgot-password"));
    }

    /**
     * Test password reset with empty secret.
     */
    @Test
    void testPasswordResetEmptySecretException() throws Exception {
        // No tenant properties mocking needed as InvalidSecretException is thrown early
        
        this.mockMvc
                .perform(post("/recovery/reset")
                        .param("password", "password")
                        .param("confirmPassword", "password")
                        .param("secret", ""))
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/invalid-secret-provided"))
                .andExpect(model().attributeExists("error"));
    }

    /**
     * Test password recovery with valid account name.
     */
    @Test
    void testPasswordForgotValidAccountName() throws Exception {
        
        this.mockMvc
                .perform(post("/recovery/forgotPassword")
                        .param("username", "username")
                        .param("accountName", "validAccountName123"))
                .andExpect(status().isOk())
                .andExpect(view().name("recovery/email-sent"))
                .andExpect(model().attributeExists("message"));
    }

    /**
     * Test password recovery with invalid account name.
     * The PatternMismatchException should be thrown and wrapped in ServletException.
     */
    @Test
    void testPasswordForgotInvalidAccountName() {
        // The controller throws PatternMismatchException for invalid account name
        // This will be wrapped in ServletException when caught by MockMvc
        Exception exception = org.junit.jupiter.api.Assertions.assertThrows(Exception.class, () -> {
            this.mockMvc
                    .perform(post("/recovery/forgotPassword")
                            .param("username", "username")
                            .param("accountName", "Invalid acc"));
        });
        
        // Verify that the root cause is PatternMismatchException
        org.junit.jupiter.api.Assertions.assertTrue(
                exception.getCause() != null && exception.getCause().toString().contains("PatternMismatchException"));
    }

    /**
     * Test password recovery with empty account name.
     */
    @Test
    void testPasswordForgotEmptyAccountName() throws Exception {
        // No tenant properties mocking needed as validation may fail before tenant access
        
        this.mockMvc.perform(post("/recovery/forgotPassword")
                        .param("username", "username")
                        .param("accountName", ""))
                .andExpect(status().isOk());
    }
}
