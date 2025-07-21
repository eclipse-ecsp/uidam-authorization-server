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
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.CaptchaProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserDto;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.response.dto.PasswordPolicyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.PasswordPolicyService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.service.impl.CaptchaServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_MAX_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_MIN_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.PRIVACY_AGREEMENT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.REDIRECT_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SELF_SIGN_UP;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.USER_CREATED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ALLOWED_SPECIALCHARS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_FIELD_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_SITE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ERROR_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.EXCLUDED_SPECIALCHARS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.IS_SIGN_UP_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MAX_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_CON_LETTERS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_DIGITS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_LOWERCASE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_SPECIALCHARS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MIN_UPPERCASE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MSG_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.PWD_NOTE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SignUpControllerTest {

    @Mock
    UserManagementClient userManagementClient;

    @Mock
    CaptchaServiceImpl captchaService;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @Mock
    private TenantProperties tenantProperties;

    private SignUpController signUpController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        signUpController = new SignUpController(userManagementClient, tenantConfigurationService,
                passwordPolicyService);
    }

    private CaptchaProperties defaultCaptchaProperties() {
        CaptchaProperties captchaProperties = new CaptchaProperties();
        captchaProperties.setRecaptchaKeySite("defaultSiteKey");
        captchaProperties.setRecaptchaKeySecret("defaultSecretKey");
        return captchaProperties;
    }

    @Test
    void selfSignUpInit_Success() {
        Model model = new ExtendedModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);
        String viewName = signUpController.selfSignUpInit(model);
        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertTrue(model.containsAttribute(MSG_LITERAL));
    }

    @Test
    void userCreated_Success() {
        Model model = new ExtendedModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);
        String viewName = signUpController.userCreated(model);
        assertEquals(USER_CREATED, viewName);
    }

    @Test
    void getPrivacyAgreementPage_Success() {
        Model model = new ExtendedModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);
        String viewName = signUpController.getPrivacyAgreementPage(model);
        assertEquals(PRIVACY_AGREEMENT, viewName);
    }

    @Test
    void addSelfUser_Success() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");
        HttpServletRequest request = new MockHttpServletRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(getUserDetailsResponse());

        ModelAndView modelAndView = signUpController.addSelfUser(userDto, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + SELF_SIGN_UP, modelAndView.getViewName());
    }

    @Test
    void addSelfUser_Success_ver_mail() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");
        HttpServletRequest request = new MockHttpServletRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(getUserDetailsResponse1());

        ModelAndView modelAndView = signUpController.addSelfUser(userDto, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + SELF_SIGN_UP, modelAndView.getViewName());
    }

    @Test
    void addSelfUserSignUpNotEnabled_Failure() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");
        HttpServletRequest request = new MockHttpServletRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class))).thenReturn(null);

        ModelAndView modelAndView = signUpController.addSelfUser(userDto, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + SELF_SIGN_UP, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
    }

    @Test
    void addSelfUser_Exception() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");
        HttpServletRequest request = new MockHttpServletRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenThrow(new RuntimeException("Exception message"));

        ModelAndView modelAndView = signUpController.addSelfUser(userDto, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + SELF_SIGN_UP, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
    }

    @Test
    void selfSignUpInit_SignUpEnabled() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        when(userManagementClient.getPasswordPolicy()).thenReturn(getPasswordPolicyDto());
        doAnswer(invocation -> {
            Model model = invocation.getArgument(0);
            model.addAttribute(PWD_NOTE, "note");
            model.addAttribute(MIN_LENGTH, DEFAULT_MIN_LENGTH);
            model.addAttribute(MAX_LENGTH, DEFAULT_MAX_LENGTH);
            model.addAttribute(MIN_CON_LETTERS, 1);
            model.addAttribute(MIN_SPECIALCHARS, 1);
            model.addAttribute(MIN_UPPERCASE, 1);
            model.addAttribute(MIN_LOWERCASE, 1);
            model.addAttribute(MIN_DIGITS, 1);
            model.addAttribute(ALLOWED_SPECIALCHARS, "!");
            model.addAttribute(EXCLUDED_SPECIALCHARS, "[]");
            return null;
        }).when(passwordPolicyService).setupPasswordPolicy(any(Model.class), any(Boolean.class));
        Model model = new ExtendedModelMap();
        String viewName = signUpController.selfSignUpInit(model);
        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_FIELD_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_SITE));
        assertTrue(model.containsAttribute(ERROR_LITERAL));
        assertTrue(model.containsAttribute(MSG_LITERAL));
        assertTrue(model.containsAttribute(PWD_NOTE));
        assertTrue(model.containsAttribute(MIN_LENGTH));
        assertTrue(model.containsAttribute(MAX_LENGTH));
        assertTrue(model.containsAttribute(MIN_CON_LETTERS));
        assertTrue(model.containsAttribute(MIN_SPECIALCHARS));
        assertTrue(model.containsAttribute(ALLOWED_SPECIALCHARS));
        assertTrue(model.containsAttribute(EXCLUDED_SPECIALCHARS));
        assertTrue(model.containsAttribute(MIN_UPPERCASE));
        assertTrue(model.containsAttribute(MIN_LOWERCASE));
        assertTrue(model.containsAttribute(MIN_DIGITS));

    }

    @Test
    void selfSignUpInit_SignUpEnabled2() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        when(userManagementClient.getPasswordPolicy()).thenReturn(getPasswordPolicyDto());
        doAnswer(invocation -> {
            Model model = invocation.getArgument(0);
            model.addAttribute(PWD_NOTE, "note");
            model.addAttribute(MIN_LENGTH, DEFAULT_MIN_LENGTH);
            model.addAttribute(MAX_LENGTH, DEFAULT_MAX_LENGTH);
            model.addAttribute(MIN_CON_LETTERS, 1);
            model.addAttribute(MIN_SPECIALCHARS, 1);
            model.addAttribute(MIN_UPPERCASE, 1);
            model.addAttribute(MIN_LOWERCASE, 1);
            model.addAttribute(MIN_DIGITS, 1);
            model.addAttribute(ALLOWED_SPECIALCHARS, "!");
            model.addAttribute(EXCLUDED_SPECIALCHARS, "[]");
            return null;
        }).when(passwordPolicyService).setupPasswordPolicy(any(Model.class), any(Boolean.class));
        Model model = new ExtendedModelMap();
        model.addAttribute(ERROR_LITERAL, "error");
        String viewName = signUpController.selfSignUpInit(model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_FIELD_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_SITE));
        assertTrue(model.containsAttribute(ERROR_LITERAL));
        assertTrue(model.containsAttribute(MSG_LITERAL));
        assertTrue(model.containsAttribute(PWD_NOTE));
        assertTrue(model.containsAttribute(MIN_LENGTH));
        assertTrue(model.containsAttribute(MAX_LENGTH));
    }

    @Test
    void selfSignUpInit_SignUpEnabledTestForZeroLengthPassword() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        when(userManagementClient.getPasswordPolicy()).thenReturn(getPasswordPolicyDtoForMinLengthZero());
        doAnswer(invocation -> {
            Model model = invocation.getArgument(0);
            model.addAttribute(PWD_NOTE, "note");
            model.addAttribute(MIN_LENGTH, 0);
            model.addAttribute(MAX_LENGTH, DEFAULT_MAX_LENGTH);
            model.addAttribute(MIN_CON_LETTERS, 1);
            model.addAttribute(MIN_SPECIALCHARS, 1);
            model.addAttribute(MIN_UPPERCASE, 1);
            model.addAttribute(MIN_LOWERCASE, 1);
            model.addAttribute(MIN_DIGITS, 1);
            model.addAttribute(ALLOWED_SPECIALCHARS, "!");
            model.addAttribute(EXCLUDED_SPECIALCHARS, "[]");
            return null;
        }).when(passwordPolicyService).setupPasswordPolicy(any(Model.class), any(Boolean.class));
        Model model = new ExtendedModelMap();
        model.addAttribute(ERROR_LITERAL, "error");
        signUpController.selfSignUpInit(model);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_FIELD_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_SITE));
        assertTrue(model.containsAttribute(ERROR_LITERAL));
        assertTrue(model.containsAttribute(MSG_LITERAL));
        assertTrue(model.containsAttribute(PWD_NOTE));
        assertTrue(model.containsAttribute(MIN_LENGTH));
        assertTrue(model.containsAttribute(MAX_LENGTH));
        assertTrue(model.containsAttribute(MIN_CON_LETTERS));
        assertTrue(model.containsAttribute(MIN_SPECIALCHARS));
        assertTrue(model.containsAttribute(ALLOWED_SPECIALCHARS));
        assertTrue(model.containsAttribute(EXCLUDED_SPECIALCHARS));
        assertTrue(model.containsAttribute(MIN_UPPERCASE));
        assertTrue(model.containsAttribute(MIN_LOWERCASE));
        assertTrue(model.containsAttribute(MIN_DIGITS));
        assertEquals(model.getAttribute(MIN_LENGTH), model.getAttribute(MIN_LENGTH));
    }

    @Test
    void selfSignUpInit_SignUpDisabled() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);

        Model model = new ExtendedModelMap();
        String viewName = signUpController.selfSignUpInit(model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertEquals(AuthorizationServerConstants.SIGN_UP_NOT_ENABLED, model.getAttribute(MSG_LITERAL));
    }

    @Test
    void selfSignUpInit_NoPasswordPolicy() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        // Password policy is handled by PasswordPolicyService, not controller
        // So we should mock the service to set attributes on the model
        doAnswer(invocation -> {
            Model model = invocation.getArgument(0);
            model.addAttribute(PWD_NOTE, "note");
            model.addAttribute(MIN_LENGTH, DEFAULT_MIN_LENGTH);
            model.addAttribute(MAX_LENGTH, DEFAULT_MAX_LENGTH);
            model.addAttribute(MIN_CON_LETTERS, 1);
            model.addAttribute(MIN_SPECIALCHARS, 1);
            model.addAttribute(MIN_UPPERCASE, 1);
            model.addAttribute(MIN_LOWERCASE, 1);
            model.addAttribute(MIN_DIGITS, 1);
            model.addAttribute(ALLOWED_SPECIALCHARS, "!");
            model.addAttribute(EXCLUDED_SPECIALCHARS, "[]");
            return null;
        }).when(passwordPolicyService).setupPasswordPolicy(any(Model.class), any(Boolean.class));
        Model model = new ExtendedModelMap();
        String viewName = signUpController.selfSignUpInit(model);
        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_FIELD_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_SITE));
        assertTrue(model.containsAttribute(ERROR_LITERAL));
        assertTrue(model.containsAttribute(MSG_LITERAL));
        assertTrue(model.containsAttribute(PWD_NOTE));
        assertEquals(DEFAULT_MIN_LENGTH, model.getAttribute(MIN_LENGTH));
        assertEquals(DEFAULT_MAX_LENGTH, model.getAttribute(MAX_LENGTH));
        assertEquals(1, model.getAttribute(MIN_CON_LETTERS));
        assertEquals(1, model.getAttribute(MIN_SPECIALCHARS));
        assertEquals(1, model.getAttribute(MIN_UPPERCASE));
        assertEquals(1, model.getAttribute(MIN_LOWERCASE));
        assertEquals(1, model.getAttribute(MIN_DIGITS));
    }

    private PasswordPolicyResponseDto getPasswordPolicyDto() {
        PasswordPolicyResponseDto passwordPolicyResponseDto = new PasswordPolicyResponseDto();
        passwordPolicyResponseDto.setMinLength(DEFAULT_MIN_LENGTH);
        passwordPolicyResponseDto.setMaxLength(DEFAULT_MAX_LENGTH);
        passwordPolicyResponseDto.setMinConsecutiveLettersLength(0);
        passwordPolicyResponseDto.setMinSpecialChars(0);
        passwordPolicyResponseDto.setAllowedSpecialChars("!@#$%^&*()_+");
        passwordPolicyResponseDto.setExcludedSpecialChars("{}[];:'\"<>,.?/\\|`~");
        passwordPolicyResponseDto.setMinUppercase(0);
        passwordPolicyResponseDto.setMinDigits(0);
        passwordPolicyResponseDto.setMinLowercase(0);
        return passwordPolicyResponseDto;
    }

    private PasswordPolicyResponseDto getPasswordPolicyDtoForMinLengthZero() {
        PasswordPolicyResponseDto passwordPolicyResponseDto = new PasswordPolicyResponseDto();
        passwordPolicyResponseDto.setMinLength(0);
        return passwordPolicyResponseDto;
    }

    private UserDetailsResponse getUserDetailsResponse() {
        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setEmail("test@example.com");
        userDetailsResponse.setVerificationEmailSent(true);
        // Set other necessary fields...
        return userDetailsResponse;
    }

    @Test
    void selfSignUpInit_SignUpEnabled_CallsPasswordPolicyService() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        Model model = new ExtendedModelMap();

        String viewName = signUpController.selfSignUpInit(model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_FIELD_ENABLED));
        assertTrue(model.containsAttribute(CAPTCHA_SITE));
        assertTrue(model.containsAttribute(ERROR_LITERAL));
        assertTrue(model.containsAttribute(MSG_LITERAL));
        // Password policy attributes are set by the service, not controller
        verify(passwordPolicyService, times(1)).setupPasswordPolicy(model, false);
    }

    @Test
    void selfSignUpInit_SignUpDisabled_SetsMessage() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);
        Model model = new ExtendedModelMap();

        String viewName = signUpController.selfSignUpInit(model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertEquals(AuthorizationServerConstants.SIGN_UP_NOT_ENABLED, model.getAttribute(MSG_LITERAL));
        // PasswordPolicyService should NOT be called
        verify(passwordPolicyService, times(0)).setupPasswordPolicy(model, false);
    }

    private UserDetailsResponse getUserDetailsResponse1() {
        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setEmail("test@example.com");
        userDetailsResponse.setVerificationEmailSent(false);
        // Set other necessary fields...
        return userDetailsResponse;
    }
}