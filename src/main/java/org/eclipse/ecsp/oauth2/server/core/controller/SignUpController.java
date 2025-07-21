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
import jakarta.validation.Valid;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserDto;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.service.PasswordPolicyService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;



import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.ADD_REQ_PAR;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.EMAIL_SENT_SUFFIX;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.FAILED_TO_CREATE_USER_WITH_USERNAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.PRIVACY_AGREEMENT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.REDIRECT_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SELF_SIGN_UP;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SIGN_UP_NOT_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SLASH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TERMS_OF_USE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.UNEXPECTED_ERROR;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.USER_CREATED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_FIELD_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_SITE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ERROR_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.IS_SIGN_UP_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MSG_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils.obtainRecaptchaResponse;

/**
 * Controller class for handling self user sign-up operations.
 */
@Controller
@RequestMapping
public class SignUpController {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignUpController.class);

    private UserManagementClient userManagementClient;

    private PasswordPolicyService passwordPolicyService;

    private TenantConfigurationService tenantConfigurationService;

    /**
     * Constructor for SelfUserController.
     *
     * @param tenantConfigurationService the service to get tenant properties
     */
    public SignUpController(UserManagementClient userManagementClient,
            TenantConfigurationService tenantConfigurationService, PasswordPolicyService passwordPolicyService) {
        this.userManagementClient = userManagementClient;
        this.tenantConfigurationService = tenantConfigurationService;
        this.passwordPolicyService = passwordPolicyService;
    }

    /**
     * Initializes the self sign-up page.
     *
     * @param model the model to add attributes to
     * @return the name of the sign-up view
     */
    @GetMapping(SLASH + SELF_SIGN_UP)
    public String selfSignUpInit(Model model) {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        model.addAttribute(IS_SIGN_UP_ENABLED, tenantProperties.isSignUpEnabled());
        if (tenantProperties.isSignUpEnabled()) {
            setupCaptcha(model);
            passwordPolicyService.setupPasswordPolicy(model, false);
        } else {
            model.addAttribute(MSG_LITERAL, SIGN_UP_NOT_ENABLED);
        }
        return SELF_SIGN_UP;
    }

    private void setupCaptcha(Model model) {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        model.addAttribute(CAPTCHA_FIELD_ENABLED, true);
        model.addAttribute(CAPTCHA_SITE, tenantProperties.getCaptcha().getRecaptchaKeySite());
        if (!model.containsAttribute(ERROR_LITERAL)) {
            model.addAttribute(ERROR_LITERAL, "");
        }
        model.addAttribute(MSG_LITERAL, "");
    }

    /**
     * Initializes the user created page.
     *
     * @param model the model to add attributes to
     * @return the name of the user-created UI view
     */

    @GetMapping(SLASH + USER_CREATED)
    public String userCreated(Model model) {
        return USER_CREATED;
    }

    /**
     * Initializes the terms of policy page.
     *
     * @return the name of the user-created UI view
     */
    @GetMapping(SLASH + TERMS_OF_USE)
    public String getTermsOfUsePage(Model model) {
        return TERMS_OF_USE;
    }

    /**
     * Initializes the privacy agreement page.
     *
     * @return the name of the user-created UI view
     */
    @GetMapping(SLASH + PRIVACY_AGREEMENT)
    public String getPrivacyAgreementPage(Model model) {
        return PRIVACY_AGREEMENT;
    }


    /**
     * Handles the submission of the self sign-up form.
     *
     * @param userDto the user data transfer object containing user details
     * @param request the HTTP servlet request
     * @param redirectAttributes the redirect attributes to add flash attributes
     * @return a ModelAndView object to redirect to the appropriate view
     */
    @PostMapping(value = SLASH + SELF_SIGN_UP, consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public ModelAndView addSelfUser(@ModelAttribute @Valid UserDto userDto, HttpServletRequest request,
                                    RedirectAttributes redirectAttributes) {
        LOGGER.info("## addSelfUser - START");
        boolean reqParametersPresent = checkForReqParameters(userDto, obtainRecaptchaResponse(request));
        if (!reqParametersPresent) {
            LOGGER.error("Required parameters are missing");
            redirectAttributes.addFlashAttribute(ERROR_LITERAL, ADD_REQ_PAR);
            return new ModelAndView(REDIRECT_LITERAL + SELF_SIGN_UP);
        }
        LOGGER.debug("Adding self user with username: {}", userDto.getFirstName());
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        if (tenantProperties.isSignUpEnabled()) {
            try {
                UserDetailsResponse userDetailsResponse = userManagementClient.selfCreateUser(userDto, request);
                if (userDetailsResponse == null) {
                    LOGGER.error(FAILED_TO_CREATE_USER_WITH_USERNAME, userDto.getUserName());
                    redirectAttributes.addFlashAttribute(ERROR_LITERAL, UNEXPECTED_ERROR);
                    return new ModelAndView(REDIRECT_LITERAL + SELF_SIGN_UP);
                } else {
                    LOGGER.info("User created successfully with username: {}", userDto.getUserName());
                    if (!userDetailsResponse.isVerificationEmailSent()) {
                        redirectAttributes.addFlashAttribute(MSG_LITERAL,
                                AuthorizationServerConstants.USER_CREATED_SUCCESSFULLY);
                    } else {
                        redirectAttributes.addFlashAttribute(MSG_LITERAL,
                                AuthorizationServerConstants.EMAIL_SENT_PREFIX
                                        + userDetailsResponse.getEmail()
                                        +
                                        "\n"
                                        +
                                        EMAIL_SENT_SUFFIX);
                    }
                    return new ModelAndView(REDIRECT_LITERAL + USER_CREATED);
                }
            } catch (Exception e) {
                LOGGER.error(FAILED_TO_CREATE_USER_WITH_USERNAME, userDto.getEmail());
                redirectAttributes.addFlashAttribute(ERROR_LITERAL, e.getMessage());
                return new ModelAndView(REDIRECT_LITERAL + SELF_SIGN_UP);
            }
        } else {
            LOGGER.debug(SIGN_UP_NOT_ENABLED);
            redirectAttributes.addFlashAttribute(MSG_LITERAL, SIGN_UP_NOT_ENABLED);
            return new ModelAndView(REDIRECT_LITERAL + SELF_SIGN_UP);
        }
    }

    private boolean checkForReqParameters(UserDto userDto, String recaptchaResp) {
        return StringUtils.hasText(userDto.getFirstName())
                && StringUtils.hasText(userDto.getEmail())
                && StringUtils.hasText(userDto.getPassword())
                && StringUtils.hasText(recaptchaResp);
    }
}
