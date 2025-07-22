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

import lombok.extern.slf4j.Slf4j;
import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.AccountProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.CaptchaProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.LoginService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
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

import java.util.Collections;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * This class tests the functionality of the LoginController with multi-tenant support.
 */
@Slf4j
@ExtendWith(MockitoExtension.class)
class LoginControllerTest {

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private LoginService loginService;

    @InjectMocks
    private LoginController loginController;

    private MockMvc mockMvc;

    /**
     * This method sets up the test environment before each test.
     * It initializes the MockMvc instance and sets up default tenant context.
     */
    @BeforeEach
    void setup() {
        TenantContext.setCurrentTenant("ecsp"); // Set default tenant for tests
        this.mockMvc = MockMvcBuilders.standaloneSetup(loginController)
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
        
        AccountProperties accountProperties = new AccountProperties();
        accountProperties.setAccountFieldEnabled(true);
        tenantProperties.setAccount(accountProperties);
        
        CaptchaProperties captchaProperties = new CaptchaProperties();
        captchaProperties.setRecaptchaKeySite("test-site-key");
        tenantProperties.setCaptcha(captchaProperties);
        
        tenantProperties.setExternalIdpEnabled(false);
        tenantProperties.setInternalLoginEnabled(true);
        tenantProperties.setSignUpEnabled(true);
        tenantProperties.setExternalIdpRegisteredClientList(Collections.emptyList());
        
        return tenantProperties;
    }

    /**
     * This test method tests the scenario where an anonymous user can access the login page.
     * It performs a GET request to the /login endpoint.
     * The test asserts that the returned status is HttpStatus.OK, the view name is "login", and the
     * "isAccountFieldEnabled" model attribute exists.
     */
    @Test
    void shouldAllowLoginPageAccessForAnonymousUser() throws Exception {
        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mockTenantProperties);
        when(loginService.isCaptchaEnabledForUserInterface()).thenReturn(false);

        this.mockMvc
            .perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attributeExists("isAccountFieldEnabled"))
            .andExpect(model().attributeExists("isCaptchaFieldEnabled"))
            .andExpect(model().attributeExists("captchaSite"))
            .andExpect(model().attributeExists("isExternalIdpEnabled"))
            .andExpect(model().attributeExists("isInternalLoginEnabled"))
            .andExpect(model().attributeExists("isIDPAutoRedirectionEnabled"))
            .andExpect(model().attributeExists("isSignUpEnabled"));
    }

    /**
     * This test method tests the login page access for a specific tenant.
     * It performs a GET request to the /login endpoint after setting a specific tenant context.
     */
    @Test
    void shouldAllowLoginPageAccessForSpecificTenant() throws Exception {
        // Setup specific tenant context
        TenantContext.setCurrentTenant("demo");
        
        // Setup mock tenant properties for demo tenant
        TenantProperties mockTenantProperties = createMockTenantProperties();
        mockTenantProperties.setExternalIdpEnabled(true);
        mockTenantProperties.setInternalLoginEnabled(false);
        
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mockTenantProperties);
        when(loginService.isCaptchaEnabledForUserInterface()).thenReturn(true);
        when(loginService.isAutoRedirectionEnabled()).thenReturn(true);

        this.mockMvc
            .perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(view().name("login"))
            .andExpect(model().attribute("isExternalIdpEnabled", true))
            .andExpect(model().attribute("isInternalLoginEnabled", false))
            .andExpect(model().attribute("isCaptchaFieldEnabled", true));
    }

    /**
     * This test method tests the scenario where an anonymous user can access the error page.
     * It performs a GET request to the /error endpoint.
     * The test asserts that the returned status is HttpStatus.OK and the view name is "error".
     */
    @Test
    void shouldAllowErrorPageAccessForAnonymousUser() throws Exception {
        this.mockMvc
            .perform(get("/error"))
            .andExpect(status().isOk())
            .andExpect(view().name("error"));
    }
}