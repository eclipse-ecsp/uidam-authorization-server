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

import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.LoginService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.UiAttributeUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

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
@RequestMapping
public class LoginController {

    private final TenantConfigurationService tenantConfigurationService;
    private final LoginService loginService;
    private final UiAttributeUtils uiAttributeUtils;

    @Value("${tenant.multitenant.enabled}")
    private boolean multitenantEnabled;

    @Value("${tenant.default}")
    private String defaultTenant;

    /**
     * The constructor for the LoginController class.
     * It initializes the required services for multi-tenant configuration and login functionality.
     *
     * @param tenantConfigurationService The service that provides the tenant configuration.
     * @param loginService The service that handles login operations.
     * @param uiAttributeUtils The utility for adding UI attributes.
     */
    public LoginController(TenantConfigurationService tenantConfigurationService, LoginService loginService,
                          UiAttributeUtils uiAttributeUtils) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.loginService = loginService;
        this.uiAttributeUtils = uiAttributeUtils;
    }

    /**
     * The endpoint for the UIDAM Login.
     * It adds additional login form attributes like account name, captcha, etc. to the model.
     * It returns the login page. Tenant properties are resolved dynamically based on current tenant context.
     *
     * @param model The Model object that is used for adding attributes.
     * @return The name of the login page.
     */
    @GetMapping({"/{tenantId}/login", "/login"})
    public String login(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            Model model, HttpServletRequest request,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(required = false) String scope,
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "response_type", required = false) String responseType,
            @RequestParam(required = false) String state) {
        // Determine tenantId based on multitenant config
        if (multitenantEnabled) {
            if (tenantId == null || tenantId.isEmpty()) {
                throw new IllegalArgumentException("TenantId is required when multi-tenant is enabled.");
            }
        } else {
            if (tenantId == null || tenantId.isEmpty()) {
                tenantId = defaultTenant;
            }
        }
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
        // Add OAuth2 parameters to model for use in login.html
        if (clientId != null) {
            model.addAttribute("client_id", clientId);
        }
        if (scope != null) {
            model.addAttribute("scope", scope);
        }
        if (redirectUri != null) {
            model.addAttribute("redirect_uri", redirectUri);
        }
        if (responseType != null) {
            model.addAttribute("response_type", responseType);
        }
        if (state != null) {
            model.addAttribute("state", state);
        }
        if (tenantId != null) {
            model.addAttribute("issuer", tenantId);
        }

        // Add UI configuration attributes
        uiAttributeUtils.addUiAttributes(model, tenantId);

        return "login";
    }

    /**
     * The endpoint for the error page.
     *
     * @param model The Model object that is used for adding attributes.
     * @return The name of the error page.
     */
    @GetMapping("/error")
    public String error(Model model) {
        // Add default UI configuration for error page since no tenant context
        uiAttributeUtils.addDefaultUiAttributes(model);
        return "error";
    }
}