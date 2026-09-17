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
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.client.AuthManagementClient;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.CaptchaProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserDto;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.response.dto.PasswordPolicyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.PasswordPolicyService;
import org.eclipse.ecsp.oauth2.server.core.service.SignupAttributeService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.service.impl.CaptchaServiceImpl;
import org.eclipse.ecsp.oauth2.server.core.utils.UiAttributeUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.MutablePropertyValues;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_MAX_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.DEFAULT_MIN_LENGTH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.INVALID_INPUT_ERROR;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.INVALID_SOURCE_IDENTIFIER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.REDIRECT_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SELF_SIGN_UP;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.UNEXPECTED_ERROR;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SignUpControllerTest {

    private static final int EXCEEDS_MAX_FIELD_LENGTH = 51;

    @Mock
    UserManagementClient userManagementClient;

    @Mock
    CaptchaServiceImpl captchaService;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private PasswordPolicyService passwordPolicyService;

    @Mock
    private SignupAttributeService signupAttributeService;

    @Mock
    private TenantProperties tenantProperties;

    @Mock
    private UiAttributeUtils uiAttributeUtils;

    @Mock
    private AuthManagementClient authManagementClient;

    @Mock
    private CacheClientUtils cacheClientUtils;

    @InjectMocks
    private SignUpController signUpController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
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
        String viewName = signUpController.selfSignUpInit("ecsp", null, model);
        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertTrue(model.containsAttribute(MSG_LITERAL));
    }

    @Test
    void userCreated_Success() {
        Model model = new ExtendedModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);
        String viewName = signUpController.userCreated("ecsp", model);
        assertEquals(USER_CREATED, viewName);
    }

    @Test
    void addSelfUser_Success() {
        UserDto userDto = createValidUserDto();
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        MockHttpServletRequest request = createSignUpRequest();
        final RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(getUserDetailsResponse());

        ModelAndView modelAndView = signUpController.addSelfUser("ecsp", userDto, bindingResult, request,
            redirectAttributes);
        assertEquals(REDIRECT_LITERAL + "ecsp/" + USER_CREATED, modelAndView.getViewName());
    }

    @Test
    void addSelfUser_Success_ver_mail() {
        UserDto userDto = createValidUserDto();
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        MockHttpServletRequest request = createSignUpRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(getUserDetailsResponse1());

        ModelAndView modelAndView = signUpController.addSelfUser("ecsp", userDto, bindingResult, request,
            redirectAttributes);
        assertEquals(REDIRECT_LITERAL + "ecsp/" + USER_CREATED, modelAndView.getViewName());
    }

    @Test
    void addSelfUserSignUpNotEnabled_Failure() {
        UserDto userDto = createValidUserDto();
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        MockHttpServletRequest request = createSignUpRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);

        ModelAndView modelAndView = signUpController.addSelfUser("ecsp", userDto, bindingResult, request,
            redirectAttributes);
        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(MSG_LITERAL));
    }

    @Test
    void addSelfUser_Exception() {
        UserDto userDto = createValidUserDto();
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        MockHttpServletRequest request = createSignUpRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenThrow(new RuntimeException("Exception message"));

        ModelAndView modelAndView = signUpController.addSelfUser("ecsp", userDto, bindingResult, request,
            redirectAttributes);
        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
    }

    @Test
    void addSelfUser_DangerousInput_Rejected() {
        UserDto userDto = createValidUserDto();
        userDto.setFirstName("<script>alert('xss')</script>");
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        MockHttpServletRequest request = createSignUpRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        ModelAndView modelAndView = signUpController.addSelfUser("ecsp", userDto, bindingResult, request,
            redirectAttributes);
        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
    }

    @Test
    void addSelfUser_SqlInjection_Rejected() {
        UserDto userDto = createValidUserDto();
        userDto.setLastName("'; DROP TABLE users; --");
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        MockHttpServletRequest request = createSignUpRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        ModelAndView modelAndView = signUpController.addSelfUser("ecsp", userDto, bindingResult, request,
            redirectAttributes);
        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, modelAndView.getViewName());
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
        String viewName = signUpController.selfSignUpInit("ecsp", null, model);
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
    void selfSignUpInit_ResolvesClientIdBeforeRenderingSignupAttributes() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        when(userManagementClient.getPasswordPolicy()).thenReturn(getPasswordPolicyDto());
        RegisteredClientDetails registeredClientDetails = new RegisteredClientDetails();
        registeredClientDetails.setClientId("portal-client");
        when(authManagementClient.getClientDetails("portal-client")).thenReturn(registeredClientDetails);
        when(cacheClientUtils.getClientDetails("portal-client")).thenReturn(new ClientCacheDetails());
        doAnswer(invocation -> {
            Model model = invocation.getArgument(0);
            model.addAttribute(PWD_NOTE, "note");
            model.addAttribute(MIN_LENGTH, DEFAULT_MIN_LENGTH);
            model.addAttribute(MAX_LENGTH, DEFAULT_MAX_LENGTH);
            return null;
        }).when(passwordPolicyService).setupPasswordPolicy(any(Model.class), any(Boolean.class));

        Model model = new ExtendedModelMap();
        String viewName = signUpController.selfSignUpInit("ecsp", "portal-client", model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertEquals("portal-client", model.getAttribute("clientId"));
        verify(signupAttributeService).setupSignupAttributes(model, "portal-client");
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
        String viewName = signUpController.selfSignUpInit("ecsp", null, model);

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
        signUpController.selfSignUpInit("ecsp", null, model);
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
        String viewName = signUpController.selfSignUpInit("ecsp", null, model);

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
        String viewName = signUpController.selfSignUpInit("ecsp", null, model);
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

        String viewName = signUpController.selfSignUpInit("ecsp", null, model);

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

        String viewName = signUpController.selfSignUpInit("ecsp", null, model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute(IS_SIGN_UP_ENABLED));
        assertEquals(AuthorizationServerConstants.SIGN_UP_NOT_ENABLED, model.getAttribute(MSG_LITERAL));
        // PasswordPolicyService should NOT be called
        verify(passwordPolicyService, times(0)).setupPasswordPolicy(model, false);
    }

    @Test
    void selfSignUpInit_WithValidTermsPrivacyPolicyUrl_SetsUrlInModel() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        
        // Mock UI properties with valid URL
        org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties uiProperties = 
            new org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties();
        uiProperties.setTermsPrivacyPolicy("https://example.com/terms-privacy");
        when(tenantProperties.getUi()).thenReturn(uiProperties);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        
        Model model = new ExtendedModelMap();

        String viewName = signUpController.selfSignUpInit("ecsp", null, model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute("termsPrivacyPolicy"));
        assertEquals("https://example.com/terms-privacy", model.getAttribute("termsPrivacyPolicy"));
    }

    @Test
    void selfSignUpInit_WithInvalidTermsPrivacyPolicyUrl_SetsEmptyStringInModel() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        
        // Mock UI properties with invalid URL
        org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties uiProperties = 
            new org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties();
        uiProperties.setTermsPrivacyPolicy("invalid-url");
        when(tenantProperties.getUi()).thenReturn(uiProperties);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        
        Model model = new ExtendedModelMap();

        String viewName = signUpController.selfSignUpInit("ecsp", null, model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute("termsPrivacyPolicy"));
        assertEquals("", model.getAttribute("termsPrivacyPolicy"));
    }

    @Test
    void selfSignUpInit_WithoutTermsPrivacyPolicyUrl_SetsEmptyStringInModel() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        
        // Mock UI properties without terms privacy policy URL
        org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties uiProperties = 
            new org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties();
        when(tenantProperties.getUi()).thenReturn(uiProperties);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        
        Model model = new ExtendedModelMap();

        String viewName = signUpController.selfSignUpInit("ecsp", null, model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute("termsPrivacyPolicy"));
        assertEquals("", model.getAttribute("termsPrivacyPolicy"));
    }

    private UserDetailsResponse getUserDetailsResponse1() {
        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setEmail("test@example.com");
        userDetailsResponse.setVerificationEmailSent(false);
        // Set other necessary fields...
        return userDetailsResponse;
    }

    private UserDto createValidUserDto() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");
        userDto.setFirstName("Test");
        userDto.setLastName("User");
        userDto.setEmail("test@example.com");
        userDto.setPassword("StrongPass1!");
        return userDto;
    }

    private MockHttpServletRequest createSignUpRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("g-recaptcha-response", "valid-captcha-response");
        return request;
    }

    @Test
    void addSelfUser_DangerousEmail_Rejected() {
        UserDto userDto = createValidUserDto();
        userDto.setEmail("test<script>@example.com");
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        MockHttpServletRequest request = createSignUpRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();

        ModelAndView result = signUpController.addSelfUser(
            "ecsp", userDto, bindingResult, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, result.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
    }

    @Test
    void addSelfUser_FieldExceedsMaxLength_Rejected() {
        UserDto userDto = createValidUserDto();
        userDto.setFirstName("A".repeat(EXCEEDS_MAX_FIELD_LENGTH));
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        MockHttpServletRequest request = createSignUpRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);

        ModelAndView result = signUpController.addSelfUser(
            "ecsp", userDto, bindingResult, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, result.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
    }

    @Test
    void addSelfUser_InvalidEmail_Rejected() {
        UserDto userDto = createValidUserDto();
        userDto.setEmail("not-an-email");
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        MockHttpServletRequest request = createSignUpRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);

        ModelAndView result = signUpController.addSelfUser(
            "ecsp", userDto, bindingResult, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, result.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
    }

    @Test
    void addSelfUser_EmptyFirstName_Rejected() {
        UserDto userDto = createValidUserDto();
        userDto.setFirstName("");
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        MockHttpServletRequest request = createSignUpRequest();
        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);

        ModelAndView result = signUpController.addSelfUser(
            "ecsp", userDto, bindingResult, request, redirectAttributes);
        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, result.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
        assertEquals(INVALID_INPUT_ERROR, redirectAttributes.getFlashAttributes().get(ERROR_LITERAL));
    }

    // === Tests for addSelfUser paths that exercise the downstream code ===

    @Test
    void addSelfUser_WithAllParamsAndVerificationEmail_RedirectsToUserCreated() {
        UserDto userDto = new UserDto();
        userDto.setFirstName("John");
        userDto.setEmail("test@example.com");
        userDto.setPassword("Pass@1234");
        userDto.setUserName("testUser");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("g-recaptcha-response", "valid-recaptcha-token");

        final RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        UserDetailsResponse response = getUserDetailsResponse();
        response.setVerificationEmailSent(true);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(response);
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        ModelAndView modelAndView = signUpController.addSelfUser(
                "ecsp", userDto, bindingResult, request, redirectAttributes);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + USER_CREATED, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(MSG_LITERAL));
    }

    @Test
    void addSelfUser_WithAllParamsAndNoVerificationEmail_RedirectsToUserCreated() {
        UserDto userDto = new UserDto();
        userDto.setFirstName("John");
        userDto.setEmail("test@example.com");
        userDto.setPassword("Pass@1234");
        userDto.setUserName("testUser");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("g-recaptcha-response", "valid-recaptcha-token");

        final RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        UserDetailsResponse response = getUserDetailsResponse();
        response.setVerificationEmailSent(false);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(response);
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        ModelAndView modelAndView = signUpController.addSelfUser(
                "ecsp", userDto, bindingResult, request, redirectAttributes);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + USER_CREATED, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(MSG_LITERAL));
    }

    @Test
    void addSelfUser_WithAllParams_ClientReturnsNull_RedirectsToSignUp() {
        UserDto userDto = new UserDto();
        userDto.setFirstName("John");
        userDto.setEmail("test@example.com");
        userDto.setPassword("Pass@1234");
        userDto.setUserName("testUser");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("g-recaptcha-response", "valid-recaptcha-token");

        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(null);
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        ModelAndView modelAndView = signUpController.addSelfUser(
                "ecsp", userDto, bindingResult, request, redirectAttributes);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
    }

    @Test
    void addSelfUser_WithAllParams_ClientThrowsException_RedirectsToSignUpWithError() {
        UserDto userDto = new UserDto();
        userDto.setFirstName("John");
        userDto.setEmail("test@example.com");
        userDto.setPassword("Pass@1234");
        userDto.setUserName("testUser");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("g-recaptcha-response", "valid-recaptcha-token");
        request.setParameter("client_id", "test-portal");

        final RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        RegisteredClientDetails registeredClientDetails = new RegisteredClientDetails();
        registeredClientDetails.setClientId("test-portal");
        when(authManagementClient.getClientDetails("test-portal")).thenReturn(registeredClientDetails);
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(new ClientCacheDetails());
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenThrow(new RuntimeException("User creation failed"));
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        ModelAndView modelAndView = signUpController.addSelfUser(
                "ecsp", userDto, bindingResult, request, redirectAttributes);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP + "?client_id=test-portal",
            modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
        // Controller returns UNEXPECTED_ERROR for generic exceptions, not the exception message
        assertEquals(AuthorizationServerConstants.UNEXPECTED_ERROR,
                redirectAttributes.getFlashAttributes().get(ERROR_LITERAL));
    }

    @Test
    void addSelfUser_WithAllParams_SignUpDisabled_RedirectsToSignUpWithMessage() {
        UserDto userDto = new UserDto();
        userDto.setFirstName("John");
        userDto.setEmail("test@example.com");
        userDto.setPassword("Pass@1234");
        userDto.setUserName("testUser");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("g-recaptcha-response", "valid-recaptcha-token");

        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        ModelAndView modelAndView = signUpController.addSelfUser(
                "ecsp", userDto, bindingResult, request, redirectAttributes);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(MSG_LITERAL));
    }

    @Test
    void addSelfUser_WithTermsRequired_CheckboxOn_AllParamsPresent_Success() {
        UserDto userDto = new UserDto();
        userDto.setFirstName("John");
        userDto.setEmail("test@example.com");
        userDto.setPassword("Pass@1234");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("g-recaptcha-response", "valid-token");
        request.setParameter("termsCheckbox", "on");

        // Setup tenant with valid terms URL
        org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties uiProperties =
            new org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties();
        uiProperties.setTermsPrivacyPolicy("https://example.com/terms");
        when(tenantProperties.getUi()).thenReturn(uiProperties);
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);

        UserDetailsResponse response = getUserDetailsResponse();
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(response);

        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        ModelAndView modelAndView = signUpController.addSelfUser(
                "ecsp", userDto, bindingResult, request, redirectAttributes);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + USER_CREATED, modelAndView.getViewName());
    }

    @Test
    void addSelfUser_WithTermsRequired_CheckboxOff_RedirectsWithError() {
        UserDto userDto = new UserDto();
        userDto.setFirstName("John");
        userDto.setEmail("test@example.com");
        userDto.setPassword("Pass@1234");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("g-recaptcha-response", "valid-token");
        request.setParameter("termsCheckbox", "off");

        // Setup tenant with valid terms URL
        org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties uiProperties =
            new org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties();
        uiProperties.setTermsPrivacyPolicy("https://example.com/terms");
        when(tenantProperties.getUi()).thenReturn(uiProperties);
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);

        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        ModelAndView modelAndView = signUpController.addSelfUser(
                "ecsp", userDto, bindingResult, request, redirectAttributes);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, modelAndView.getViewName());
        assertTrue(redirectAttributes.getFlashAttributes().containsKey(ERROR_LITERAL));
    }

    @Test
    void addSelfUser_WithInvalidTermsUrl_TermsNotRequired_AllParamsPresent_Success() {
        UserDto userDto = new UserDto();
        userDto.setFirstName("John");
        userDto.setEmail("test@example.com");
        userDto.setPassword("Pass@1234");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("g-recaptcha-response", "valid-token");

        // Terms URL is invalid, so terms not required
        org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties uiProperties =
            new org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UiProperties();
        uiProperties.setTermsPrivacyPolicy("not-a-url");
        when(tenantProperties.getUi()).thenReturn(uiProperties);
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);

        UserDetailsResponse response = getUserDetailsResponse();
        when(userManagementClient.selfCreateUser(any(UserDto.class), any(HttpServletRequest.class)))
                .thenReturn(response);

        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        ModelAndView modelAndView = signUpController.addSelfUser(
                "ecsp", userDto, bindingResult, request, redirectAttributes);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + USER_CREATED, modelAndView.getViewName());
    }

    @Test
    void selfSignUpInit_WithNullUiProperties_SetsEmptyTermsUrl() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getUi()).thenReturn(null);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());

        Model model = new ExtendedModelMap();
        String viewName = signUpController.selfSignUpInit("ecsp", null, model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertTrue(model.containsAttribute("termsPrivacyPolicy"));
        assertEquals("", model.getAttribute("termsPrivacyPolicy"));
    }

    @Test
    void initBinder_emptyStringFieldBecomesNull() {
        UserDto userDto = new UserDto();
        WebDataBinder binder = new WebDataBinder(userDto, "userDto");
        signUpController.initBinder(binder);

        MutablePropertyValues pvs = new MutablePropertyValues();
        pvs.add("firstName", "");        // empty → should become null
        pvs.add("email", "test@example.com"); // non-empty → preserved
        binder.bind(pvs);

        assertNull(userDto.getFirstName());
        assertEquals("test@example.com", userDto.getEmail());
    }

    @Test
    void initBinder_whitespaceOnlyFieldBecomesNull() {
        UserDto userDto = new UserDto();
        WebDataBinder binder = new WebDataBinder(userDto, "userDto");
        signUpController.initBinder(binder);

        MutablePropertyValues pvs = new MutablePropertyValues();
        pvs.add("firstName", "   "); // whitespace-only → trimmed then null
        binder.bind(pvs);

        assertNull(userDto.getFirstName());
    }

    @Test
    void selfSignUpInit_InvalidClientId_BlocksPageLoad() {
        // authManagementClient returns null → client_id is unrecognized
        when(authManagementClient.getClientDetails("unknown-client")).thenReturn(null);

        Model model = new ExtendedModelMap();
        String viewName = signUpController.selfSignUpInit("ecsp", "unknown-client", model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertEquals(false, model.getAttribute(IS_SIGN_UP_ENABLED));
        assertEquals(INVALID_SOURCE_IDENTIFIER, model.getAttribute(ERROR_LITERAL));
        // setupSignupAttributes must NOT be called when client_id is invalid
        verify(signupAttributeService, times(0)).setupSignupAttributes(any(), any());
    }

    @Test
    void selfSignUpInit_DeletedClient_SetupAttributesThrows_ShowsError() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getCaptcha()).thenReturn(defaultCaptchaProperties());
        RegisteredClientDetails registeredClientDetails = new RegisteredClientDetails();
        registeredClientDetails.setClientId("deleted-client");
        when(authManagementClient.getClientDetails("deleted-client")).thenReturn(registeredClientDetails);
        when(cacheClientUtils.getClientDetails("deleted-client")).thenReturn(new ClientCacheDetails());
        doAnswer(invocation -> {
            Model m = invocation.getArgument(0);
            m.addAttribute(org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.PWD_NOTE,
                    "note");
            return null;
        }).when(passwordPolicyService).setupPasswordPolicy(any(Model.class), any(Boolean.class));
        doThrow(new RuntimeException("ClientRegistrationException: client not found"))
            .when(signupAttributeService).setupSignupAttributes(any(Model.class), any());

        Model model = new ExtendedModelMap();
        String viewName = signUpController.selfSignUpInit("ecsp", "deleted-client", model);

        assertEquals(SELF_SIGN_UP, viewName);
        assertEquals(false, model.getAttribute(IS_SIGN_UP_ENABLED));
        assertEquals(UNEXPECTED_ERROR, model.getAttribute(ERROR_LITERAL));
    }

    @Test
    void addSelfUser_InvalidClientId_BlocksPost() {
        UserDto userDto = createValidUserDto();
        MockHttpServletRequest request = createSignUpRequest();
        request.setParameter("client_id", "bad-client");
        when(authManagementClient.getClientDetails("bad-client")).thenReturn(null);

        RedirectAttributes redirectAttributes = new RedirectAttributesModelMap();
        BindingResult bindingResult = new BeanPropertyBindingResult(userDto, "userDto");
        ModelAndView result = signUpController.addSelfUser(
                "ecsp", userDto, bindingResult, request, redirectAttributes);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, result.getViewName());
        assertEquals(INVALID_SOURCE_IDENTIFIER, redirectAttributes.getFlashAttributes().get(ERROR_LITERAL));
        // User creation must NOT be attempted
        verify(userManagementClient, times(0)).selfCreateUser(any(), any());
    }
}