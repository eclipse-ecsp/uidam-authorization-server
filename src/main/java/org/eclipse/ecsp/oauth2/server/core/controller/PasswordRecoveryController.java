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


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.UpdatePasswordData;
import org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.InvalidSecretException;
import org.eclipse.ecsp.oauth2.server.core.exception.PasswordRecoveryException;
import org.eclipse.ecsp.oauth2.server.core.exception.UserNotFoundException;
import org.eclipse.ecsp.oauth2.server.core.service.PasswordPolicyService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.service.impl.CaptchaServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.BAD_REQUEST_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.RECOVERY_CHANGE_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.RECOVERY_EMAIL_SENT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.RECOVERY_FORGOT_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.RECOVERY_INV_SECRET;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.RECOVERY_PASSWORD_CHANGED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SECRET_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_FIELD_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_SITE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.EMPTY_STRING;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ERROR_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils.isAccountNamePatternValid;
import static org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils.obtainRecaptchaResponse;

/**
 * The PasswordRecoveryController class is a Spring MVC Controller that handles password recovery operations.
 * It provides endpoints for initializing the password recovery process, submitting the password recovery form,
 * resetting the password using a link received in an email, and updating the password in the system.
 */
@Controller
@RequestMapping("/recovery")
public class PasswordRecoveryController {
    private static final Logger LOGGER = LoggerFactory.getLogger(PasswordRecoveryController.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final int ERROR_MESSAGE_KEY_LENGTH = 10;

    private final TenantConfigurationService tenantConfigurationService;
    private final UserManagementClient userManagementClient;
    private final CaptchaServiceImpl captchaServiceImpl;
    private final PasswordPolicyService passwordPolicyService;

    /**
     * This is the constructor for the PasswordRecoveryController class.
     * It initializes the required services for multi-tenant configuration and password recovery functionality.
     *
     * @param tenantConfigurationService The service that provides the tenant configuration.
     * @param userManagementClient The client for user management operations.
     * @param captchaServiceImpl The service for captcha processing.
     * @param passwordPolicyService The service for password policy management.
     */
    @Autowired
    public PasswordRecoveryController(TenantConfigurationService tenantConfigurationService,
            UserManagementClient userManagementClient,
            CaptchaServiceImpl captchaServiceImpl,
            PasswordPolicyService passwordPolicyService) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.userManagementClient = userManagementClient;
        this.captchaServiceImpl = captchaServiceImpl;
        this.passwordPolicyService = passwordPolicyService;
    }

    private static final String MESSAGE_LITERAL = "message";
    private static final String SECRET_KEY_IS_NULL = "Secret key is null";

    /**
     * This method is used to initialize the password recovery process.
     * It is a GET request handler that loads the forgot-password page.
     * It also adds captcha related attributes to the model.
     * Tenant properties are resolved dynamically based on current tenant context.
     *
     * @param model The Model object to bind to the view.
     * @return A string representing the name of the view to be returned.
     */
    @GetMapping
    public String passwordInit(Model model) {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        
        model.addAttribute(CAPTCHA_FIELD_ENABLED, true);
        model.addAttribute(CAPTCHA_SITE, tenantProperties.getCaptcha().getRecaptchaKeySite());
        return RECOVERY_FORGOT_PASSWORD;
    }

    /**
     * This method handles the POST request for the password recovery operation - load forgot password form where user
     * can provide input to get recovery link.
     * It validates the captcha response, sends a password recovery email to the user, and returns a ModelAndView
     * object.
     *
     * @param request The HttpServletRequest object that contains the request the client made of the servlet.
     * @param username The username provided by the user.
     * @param accountName The account name provided by the user.
     * @param model The Model object to bind to the view.
     * @return A ModelAndView object that includes the view name and model attributes.
     * @throws MalformedURLException If the password recovery URL is not a valid URL.
     */
    @PostMapping("/forgotPassword")
    public ModelAndView passwordForgot(HttpServletRequest request, @RequestParam("username") String username,
                                       @RequestParam("accountName") String accountName, Model model)
            throws MalformedURLException {

        isAccountNamePatternValid(accountName);

        String recaptchaResponse = obtainRecaptchaResponse(request);
        recaptchaResponse = (recaptchaResponse != null) ? recaptchaResponse : EMPTY_STRING;
        if (!StringUtils.isEmpty(recaptchaResponse)) {
            captchaServiceImpl.processResponse(recaptchaResponse, request);
        }
        LOGGER.info("sending email notification with recovery secret to reset password");
        userManagementClient.sendUserResetPasswordNotification(username, accountName);
        model.addAttribute(MESSAGE_LITERAL, IgniteOauth2CoreConstants.PASSWORD_RECOVERY_EMAIL_SENT);
        return new ModelAndView(RECOVERY_EMAIL_SENT).addObject(model);
    }

    /**
     * This method handles the GET request for the password reset operation - load password reset page with link
     * received in email notification.
     * It decodes the encoded parameters from the URL, validates the secret key, and returns a ModelAndView object.
     * Tenant properties are resolved dynamically based on current tenant context.
     *
     * @param encodedParams The encoded parameters from the URL. They include the secret key for password reset.
     * @param model The Model object to bind to the view.
     * @return A ModelAndView object that includes the view name and model attributes.
     * @throws UnsupportedEncodingException If the character encoding is not supported.
     */
    @GetMapping("reset/{encodedParams}")
    public ModelAndView changePassword(@PathVariable("encodedParams") String encodedParams, Model model
    ) throws UnsupportedEncodingException {

        String decodedParams;
        try {
            decodedParams = new String(Base64.getDecoder().decode(encodedParams), StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOGGER.error("Cannot perform operation, invalid secret provided", e);
            throw new InvalidSecretException(IgniteOauth2CoreConstants.INVALID_SECRET_PROVIDED);
        }
        String[] params = decodedParams.split("&");
        String secret = params[0].substring("secret=".length());
        if (StringUtils.isEmpty(secret)) {
            LOGGER.error(SECRET_KEY_IS_NULL);
            throw new InvalidSecretException(IgniteOauth2CoreConstants.INVALID_SECRET_PROVIDED);
        }

        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();

        model.addAttribute(SECRET_LITERAL, secret);
        model.addAttribute(CAPTCHA_FIELD_ENABLED, true);
        model.addAttribute(CAPTCHA_SITE, tenantProperties.getCaptcha().getRecaptchaKeySite());
        passwordPolicyService.setupPasswordPolicy(model, true);
        return new ModelAndView(RECOVERY_CHANGE_PASSWORD).addObject(model);
    }

    /**
     * This method handles the POST request for the password update operation.
     * It validates the secret key, updates the user's password in the system, and returns a ModelAndView object.
     * Tenant properties are resolved dynamically based on current tenant context.
     *
     * @param request The HttpServletRequest object that contains the request the client made of the servlet.
     * @param password The new password provided by the user.
     * @param confirmPassword The confirmation of the new password provided by the user.
     * @param secret The secret key for password reset.
     * @return A ModelAndView object that includes the view name and model attributes.
     * @throws JsonMappingException If there is a problem with the JSON mapping.
     * @throws JsonProcessingException If there is a problem processing the JSON content.
     */
    @PostMapping("/reset")
    public ModelAndView updatePassword(HttpServletRequest request, @RequestParam String password,
                                       @RequestParam String confirmPassword, @RequestParam String secret)
            throws JsonProcessingException {

        if (StringUtils.isEmpty(secret)) {
            LOGGER.error(SECRET_KEY_IS_NULL);
            throw new InvalidSecretException(IgniteOauth2CoreConstants.INVALID_SECRET_PROVIDED);
        }

        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();

        String recaptchaResponse = obtainRecaptchaResponse(request);
        recaptchaResponse = (recaptchaResponse != null) ? recaptchaResponse : EMPTY_STRING;

        if (!StringUtils.isEmpty(recaptchaResponse)) {
            captchaServiceImpl.processResponse(recaptchaResponse, request);
        }
        ModelAndView errorResult = new ModelAndView(RECOVERY_CHANGE_PASSWORD, SECRET_LITERAL, secret);
        if (!password.equals(confirmPassword)) {
            errorResult.addObject(CAPTCHA_FIELD_ENABLED, true);
            errorResult.addObject(CAPTCHA_SITE, tenantProperties.getCaptcha().getRecaptchaKeySite());

            return errorResult.addObject(ERROR_LITERAL, IgniteOauth2CoreConstants.PASSWORD_DID_NOT_MATCH);
        }
        try {
            userManagementClient.updateUserPasswordUsingRecoverySecret(UpdatePasswordData.of(secret, confirmPassword));
        } catch (Exception ex) {
            if (ex.getMessage().contains(BAD_REQUEST_LITERAL)) {
                return new ModelAndView(RECOVERY_CHANGE_PASSWORD, SECRET_LITERAL, secret)
                        .addObject(ERROR_LITERAL,
                                getErrorMessage(ex))
                        .addObject(CAPTCHA_FIELD_ENABLED, true)
                        .addObject(CAPTCHA_SITE, tenantProperties.getCaptcha().getRecaptchaKeySite());
            }
            return new ModelAndView(RECOVERY_FORGOT_PASSWORD).addObject(ERROR_LITERAL, ex.getMessage())
                    .addObject(CAPTCHA_FIELD_ENABLED, true)
                    .addObject(CAPTCHA_SITE, tenantProperties.getCaptcha().getRecaptchaKeySite());

        }
        return new ModelAndView(RECOVERY_PASSWORD_CHANGED).addObject(MESSAGE_LITERAL,
                IgniteOauth2CoreConstants.PASSWORD_UPDATED_SUCCESSFULLY);

    }

    /**
     * This method is used to extract the error message from an exception.
     * It reads the JSON content from the exception message and extracts the error message.
     *
     * @param ex The exception from which the error message is to be extracted.
     * @return A string representing the error message.
     * @throws JsonProcessingException If there is a problem processing the JSON content.
     * @throws JsonMappingException If there is a problem with the JSON mapping.
     */
    private String getErrorMessage(Exception ex) throws JsonProcessingException {
        String message = OBJECT_MAPPER.readTree(ex.getMessage()).get(MESSAGE_LITERAL).asText();
        String errorMessage = message.substring(ERROR_MESSAGE_KEY_LENGTH);
        return errorMessage.split("'")[0];
    }

    /**
     * This method is an exception handler for the UserNotFoundException.
     * It is triggered when a UserNotFoundException is thrown in the application.
     * It adds the necessary attributes to the model and returns a ModelAndView object that includes the view name and
     * model attributes. Tenant properties are resolved dynamically based on current tenant context.
     *
     * @param model The Model object to bind to the view.
     * @return A ModelAndView object that includes the view name and model attributes.
     */
    @ExceptionHandler(UserNotFoundException.class)
    public ModelAndView handleUserNotFound(Model model) {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        
        model.addAttribute(CAPTCHA_FIELD_ENABLED, true);
        model.addAttribute(CAPTCHA_SITE, tenantProperties.getCaptcha().getRecaptchaKeySite());
        model.addAttribute(ERROR_LITERAL, IgniteOauth2CoreConstants.USER_DETAILS_NOT_FOUND);
        return new ModelAndView(RECOVERY_FORGOT_PASSWORD);
    }

    /**
     * This method is an exception handler for the InvalidSecretException.
     * It is triggered when an InvalidSecretException is thrown in the application.
     * It adds the necessary attributes to the model and returns a ModelAndView object that includes the view name and
     * model attributes.
     *
     * @param model The Model object to bind to the view.
     * @return A ModelAndView object that includes the view name and model attributes.
     */
    @ExceptionHandler(InvalidSecretException.class)
    public ModelAndView invalidSecretProvided(Model model) {
        model.addAttribute(ERROR_LITERAL, IgniteOauth2CoreConstants.INVALID_SECRET_PROVIDED);
        return new ModelAndView(RECOVERY_INV_SECRET);
    }
    
    /**
     * This method is an exception handler for the PasswordRecoveryException.
     * It is triggered when a PasswordRecoveryException is thrown in the application.
     * It returns a ModelAndView object that includes the view name and model attributes.
     * Tenant properties are resolved dynamically based on current tenant context.
     *
     * @return A ModelAndView object that includes the view name and model attributes.
     */
    @ExceptionHandler(PasswordRecoveryException.class)
    public ModelAndView passwordRecoveryException() {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        
        return new ModelAndView(RECOVERY_FORGOT_PASSWORD)
                .addObject(ERROR_LITERAL, IgniteOauth2CoreConstants.PASSWORD_RECOVERY_EMAIL_SENT_FAILURE)
                .addObject(CAPTCHA_FIELD_ENABLED, true)
                .addObject(CAPTCHA_SITE, tenantProperties.getCaptcha().getRecaptchaKeySite());
    }
}
