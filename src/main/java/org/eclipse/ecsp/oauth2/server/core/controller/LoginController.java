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


import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.LoginService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ACCOUNT_FIELD_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_FIELD_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_SITE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.EXTERNAL_IDP_AUTHORIZATION_URI;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.EXTERNAL_IDP_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.EXTERNAL_IDP_LIST;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.IDP_AUTHORIZATION_URI;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.INTERNAL_LOGIN_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.IS_IDP_AUTO_REDIRECTION_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.IS_SIGN_UP_ENABLED;

/**
 * The LoginController class is a REST controller that manages the login process for the UIDAM default login page.
 * It exposes the /login and /error endpoints for this purpose.
 */
@Controller
public class LoginController {

    private final TenantConfigurationService tenantConfigurationService;
    private final LoginService loginService;

    /**
     * The constructor for the LoginController class.
     * It initializes the required services for multi-tenant configuration and login functionality.
     *
     * @param tenantConfigurationService The service that provides the tenant configuration.
     * @param loginService The service that handles login operations.
     */
    @Autowired
    public LoginController(TenantConfigurationService tenantConfigurationService, LoginService loginService) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.loginService = loginService;
    }

    /**
     * The endpoint for the UIDAM Login.
     * It adds additional login form attributes like account name, captcha, etc. to the model.
     * It returns the login page. Tenant properties are resolved dynamically based on current tenant context.
     *
     * @param model The Model object that is used for adding attributes.
     * @return The name of the login page.
     */
    @GetMapping("/login")
    public String login(Model model) {
        // Get tenant properties dynamically based on current tenant context
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        model.addAttribute(ACCOUNT_FIELD_ENABLED, tenantProperties.getAccount().getAccountFieldEnabled());
        boolean isCaptchaEnabledForUserInterface = loginService.isCaptchaEnabledForUserInterface();
        model.addAttribute(CAPTCHA_FIELD_ENABLED, isCaptchaEnabledForUserInterface);
        model.addAttribute(CAPTCHA_SITE, tenantProperties.getCaptcha().getRecaptchaKeySite());

        model.addAttribute(EXTERNAL_IDP_ENABLED, tenantProperties.isExternalIdpEnabled());
        model.addAttribute(INTERNAL_LOGIN_ENABLED, tenantProperties.isInternalLoginEnabled());
        model.addAttribute(IS_IDP_AUTO_REDIRECTION_ENABLED, false);
        model.addAttribute(IS_SIGN_UP_ENABLED, tenantProperties.isSignUpEnabled());
        if (tenantProperties.isExternalIdpEnabled()) {
            model.addAttribute(EXTERNAL_IDP_LIST, tenantProperties.getExternalIdpRegisteredClientList());
            model.addAttribute(EXTERNAL_IDP_AUTHORIZATION_URI, IDP_AUTHORIZATION_URI);
            if (!tenantProperties.isInternalLoginEnabled()) {
                model.addAttribute(IS_IDP_AUTO_REDIRECTION_ENABLED, loginService.isAutoRedirectionEnabled());
            }
        }
        return "login";
    }

    /**
     * The endpoint for the error page.
     *
     * @return The name of the error page.
     */
    @GetMapping("/error")
    public String error() {
        return "error";
    }
}