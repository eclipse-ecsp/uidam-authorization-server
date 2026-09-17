/*******************************************************************************
 * Copyright (c) 2023-24 Harman International
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.controller;

import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.client.AuthManagementClient;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.SignupClientConfig;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserDto;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.service.PasswordPolicyService;
import org.eclipse.ecsp.oauth2.server.core.service.SignupAttributeService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.UiAttributeUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import java.util.Collections;
import java.util.List;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.INVALID_INPUT_ERROR;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.INVALID_SOURCE_IDENTIFIER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.REDIRECT_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SELF_SIGN_UP;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.USER_CREATED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ERROR_LITERAL;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the new signup-config features in {@link SignUpController}.
 *
 * <p>Covers:
 * <ul>
 *   <li>{@code resolveValidClientId} — OAuth2 client validation</li>
 *   <li>{@code applyClientSignupConfig} — defaultRoles, defaultAccount,
 *       userStatus, customAttributeListMap</li>
 *   <li>POST handler — validateCustomAttributeKeys called before config</li>
 * </ul>
 */
class SignUpControllerSignupConfigTest {

    @Mock
    private UserManagementClient userManagementClient;
    @Mock
    private TenantConfigurationService tenantConfigurationService;
    @Mock
    private TenantProperties tenantProperties;
    @Mock
    private PasswordPolicyService passwordPolicyService;
    @Mock
    private SignupAttributeService signupAttributeService;
    @Mock
    private UiAttributeUtils uiAttributeUtils;
    @Mock
    private AuthManagementClient authManagementClient;

    @Mock
    private CacheClientUtils cacheClientUtils;

    @InjectMocks
    private SignUpController controller;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.isSignUpEnabled()).thenReturn(true);
        when(tenantProperties.getSignupConfigList()).thenReturn(Collections.emptyList());
        // Ensure tests see the signup additional-attributes feature enabled by default
        org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.SignupProperties signupProps =
                new org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.SignupProperties();
        signupProps.setAdditionalAttributesEnabled(true);
        when(tenantProperties.getSignup()).thenReturn(signupProps);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private UserDto validUserDto() {
        UserDto dto = new UserDto();
        dto.setFirstName("Alice");
        dto.setLastName("Smith");
        dto.setEmail("alice@example.com");
        dto.setPassword("Secure123!");
        dto.setUserName("alice@example.com");
        return dto;
    }

    private MockHttpServletRequest signupRequest(String clientId) {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setParameter("g-recaptcha-response", "valid-captcha");
        if (clientId != null) {
            req.setParameter("client_id", clientId);
        }
        return req;
    }

    private RegisteredClientDetails registeredClient(String clientId) {
        RegisteredClientDetails details = new RegisteredClientDetails();
        details.setClientId(clientId);
        return details;
    }

    private SignupClientConfig clientConfig(String clientId, String roles,
            String account, String status, String customMap) {
        SignupClientConfig cfg = new SignupClientConfig();
        cfg.setClientId(clientId);
        cfg.setDefaultRoles(roles);
        cfg.setDefaultAccount(account);
        cfg.setUserStatus(status);
        cfg.setCustomAttributeListMap(customMap);
        return cfg;
    }

    private ClientCacheDetails validClientCacheDetails() {
        return new ClientCacheDetails();
    }

    // -----------------------------------------------------------------------
    // resolveValidClientId — via addSelfUser POST (client_id read from request)
    // -----------------------------------------------------------------------

    @Test
    void post_noClientId_noClientConfigApplied_userCreatedSuccessfully() {
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        ModelAndView mav = controller.addSelfUser("ecsp", dto, br, signupRequest(null), ra);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + USER_CREATED, mav.getViewName());
        // signupDefaultAccount and signupSourceClientId must NOT be set
        assertNull(dto.getAdditionalAttributes().get("signupSourceClientId"));
        verify(signupAttributeService, never()).validateCustomAttributeKeys(anyString());
    }

    @Test
    void post_clientIdNotRegistered_treatedAsNull_noConfigApplied() {
        // getClientDetails returns null → clientId is unrecognized, signup is blocked
        when(authManagementClient.getClientDetails("unknown-portal")).thenReturn(null);

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        ModelAndView mav = controller.addSelfUser("ecsp", dto, br,
                signupRequest("unknown-portal"), ra);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, mav.getViewName());
        assertEquals(INVALID_SOURCE_IDENTIFIER,
                ra.getFlashAttributes().get(ERROR_LITERAL));
        verify(signupAttributeService, never()).validateCustomAttributeKeys(anyString());
        verify(userManagementClient, never()).selfCreateUser(any(), any());
    }

    @Test
    void post_unsafeClientId_treatedAsNull() {
        // client_id contains script tag — InputSanitizer.isSafe returns false → signup is blocked
        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        MockHttpServletRequest req = signupRequest(null);
        req.setParameter("client_id", "<script>alert(1)</script>");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        ModelAndView mav = controller.addSelfUser("ecsp", dto, br, req, ra);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, mav.getViewName());
        assertEquals(INVALID_SOURCE_IDENTIFIER,
                ra.getFlashAttributes().get(ERROR_LITERAL));
        verify(userManagementClient, never()).selfCreateUser(any(), any());
    }

    // -----------------------------------------------------------------------
    // applyClientSignupConfig — defaultRoles applied
    // -----------------------------------------------------------------------

    @Test
    void post_validClientId_defaultRolesApplied() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        SignupClientConfig cfg = clientConfig("test-portal", "VEHICLE_OWNER", null, null, null);
        when(tenantProperties.getSignupConfigList())
                .thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        assertEquals(List.of("VEHICLE_OWNER"), dto.getRoles());
    }

    @Test
    void post_validClientId_multipleDefaultRolesApplied() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        SignupClientConfig cfg = clientConfig("test-portal", "ROLE_A, ROLE_B", null, null, null);
        when(tenantProperties.getSignupConfigList())
                .thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        assertNotNull(dto.getRoles());
        assertEquals(2, dto.getRoles().size());
        assertTrue(dto.getRoles().contains("ROLE_A"));
        assertTrue(dto.getRoles().contains("ROLE_B"));
    }

    // -----------------------------------------------------------------------
    // applyClientSignupConfig — defaultAccount applied
    // -----------------------------------------------------------------------

    @Test
    void post_validClientId_defaultAccountApplied() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        SignupClientConfig cfg = clientConfig("test-portal", null, "userdefaultaccount", null, null);
        when(tenantProperties.getSignupConfigList())
                .thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        assertEquals("userdefaultaccount", dto.getAdditionalAttributes().get("signupDefaultAccount"));
    }

    // -----------------------------------------------------------------------
    // applyClientSignupConfig — userStatus applied
    // -----------------------------------------------------------------------

    @Test
    void post_validClientId_userStatusApplied() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        SignupClientConfig cfg = clientConfig("test-portal", null, null, "pending", null);
        when(tenantProperties.getSignupConfigList())
                .thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        assertEquals("PENDING", dto.getStatus());
    }

    @Test
    void post_userStatusActive_uppercasedAndApplied() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        SignupClientConfig cfg = clientConfig("test-portal", null, null, " active ", null);
        when(tenantProperties.getSignupConfigList())
                .thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        assertEquals("ACTIVE", dto.getStatus());
    }

    @Test
    void post_userStatusBlank_statusNotSet() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        SignupClientConfig cfg = clientConfig("test-portal", null, null, "", null);
        when(tenantProperties.getSignupConfigList())
                .thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        assertNull(dto.getStatus());
    }

    @Test
    void post_userStatusNull_statusNotSet() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        SignupClientConfig cfg = clientConfig("test-portal", null, null, null, null);
        when(tenantProperties.getSignupConfigList())
                .thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        assertNull(dto.getStatus());
    }

    // -----------------------------------------------------------------------
    // applyClientSignupConfig — customAttributeListMap auto-populated
    // -----------------------------------------------------------------------

    @Test
    void post_customAttributeListMap_valuesSetOnDto() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        SignupClientConfig cfg = clientConfig("test-portal", null, null, null,
                "custom:companyName#Samsung,custom:companyAddress#Seoul");
        when(tenantProperties.getSignupConfigList())
                .thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        assertEquals("Samsung", dto.getAdditionalAttributes().get("custom:companyName"));
        assertEquals("Seoul", dto.getAdditionalAttributes().get("custom:companyAddress"));
    }

    @Test
    void post_customAttributeListMap_entryWithoutHash_ignored() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        SignupClientConfig cfg = clientConfig("test-portal", null, null, null,
                "custom:companyName#Samsung,invalidEntry");
        when(tenantProperties.getSignupConfigList())
                .thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        assertEquals("Samsung", dto.getAdditionalAttributes().get("custom:companyName"));
        assertNull(dto.getAdditionalAttributes().get("invalidEntry"));
    }

    // -----------------------------------------------------------------------
    // signupSourceClientId stamped when clientId is valid
    // -----------------------------------------------------------------------

    @Test
    void post_validClientId_signupSourceClientIdStamped() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        assertEquals("test-portal", dto.getAdditionalAttributes().get("signupSourceClientId"));
    }

    // -----------------------------------------------------------------------
    // validateCustomAttributeKeys — called before applyClientSignupConfig
    // -----------------------------------------------------------------------

    @Test
    void post_validateCustomAttrKeysCalledBeforeConfig() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        // validateCustomAttributeKeys throws — config must never be applied
        doThrow(new IllegalStateException("bad key"))
                .when(signupAttributeService).validateCustomAttributeKeys("test-portal");

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        ModelAndView mav = controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        // Must redirect with error
        assertTrue(mav.getViewName().contains(SELF_SIGN_UP));
        assertEquals(INVALID_INPUT_ERROR, ra.getFlashAttributes().get(ERROR_LITERAL));
        // Roles must NOT be set (config never applied)
        assertNull(dto.getRoles());
    }

    @Test
    void post_unknownCustomAttrKey_redirectsWithInvalidInputError() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        doThrow(new IllegalStateException("customAttributeListMap: key(s) [badKey] not defined"))
                .when(signupAttributeService).validateCustomAttributeKeys("test-portal");

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        ModelAndView mav = controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP + "?client_id=test-portal",
                mav.getViewName());
        assertEquals(INVALID_INPUT_ERROR, ra.getFlashAttributes().get(ERROR_LITERAL));
    }

    // -----------------------------------------------------------------------
    // No config entry for clientId — no roles/account/status applied
    // -----------------------------------------------------------------------

    @Test
    void post_validClientId_noMatchingConfig_noRolesOrStatusApplied() {
        when(authManagementClient.getClientDetails("other-portal"))
                .thenReturn(registeredClient("other-portal"));
        when(cacheClientUtils.getClientDetails("other-portal")).thenReturn(validClientCacheDetails());
        // Config list has an entry but for a different clientId
        when(tenantProperties.getSignupConfigList())
                .thenReturn(List.of(clientConfig("test-portal", "ROLE_A", "acct", "PENDING", null)));
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, signupRequest("other-portal"), ra);

        assertNull(dto.getRoles());
        assertNull(dto.getStatus());
    }

    // -----------------------------------------------------------------------
    // additional attribute params extracted from form request
    // -----------------------------------------------------------------------

    @Test
    void post_signupAttrParams_addedToAdditionalAttributes() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        MockHttpServletRequest req = signupRequest("test-portal");
        req.setParameter("nickName", "alicia");
        req.setParameter("age", "30");

        controller.addSelfUser("ecsp", dto, br, req, ra);

        assertEquals("alicia", dto.getAdditionalAttributes().get("nickName"));
        assertEquals("30", dto.getAdditionalAttributes().get("age"));
    }

    @Test
    void post_unsafeSignupAttrValue_notAdded() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        MockHttpServletRequest req = signupRequest("test-portal");
        req.setParameter("xss", "<script>alert(1)</script>");

        controller.addSelfUser("ecsp", dto, br, req, ra);

        assertNull(dto.getAdditionalAttributes().get("xss"));
    }

    // -----------------------------------------------------------------------
    // clientId case-insensitive config lookup
    // -----------------------------------------------------------------------

    @Test
    void post_clientIdCaseInsensitive_configApplied() {
        when(authManagementClient.getClientDetails("Test-Portal"))
                .thenReturn(registeredClient("Test-Portal"));
        when(cacheClientUtils.getClientDetails("Test-Portal")).thenReturn(validClientCacheDetails());
        SignupClientConfig cfg = clientConfig("TEST-PORTAL", "ROLE_X", null, null, null);
        when(tenantProperties.getSignupConfigList())
                .thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("Test-Portal")).thenReturn(cfg);
        when(userManagementClient.selfCreateUser(any(), any()))
                .thenReturn(new UserDetailsResponse());

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        MockHttpServletRequest req = signupRequest(null);
        req.setParameter("client_id", "Test-Portal");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        controller.addSelfUser("ecsp", dto, br, req, ra);

        assertEquals(List.of("ROLE_X"), dto.getRoles());
    }

    // -----------------------------------------------------------------------
    // redirect URL contains client_id when clientId is valid
    // -----------------------------------------------------------------------

    @Test
    void post_signupDisabled_redirectContainsClientId() {
        when(authManagementClient.getClientDetails("test-portal"))
                .thenReturn(registeredClient("test-portal"));
        when(cacheClientUtils.getClientDetails("test-portal")).thenReturn(validClientCacheDetails());
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        ModelAndView mav = controller.addSelfUser("ecsp", dto, br, signupRequest("test-portal"), ra);

        // Redirect URL must include client_id query param
        assertTrue(mav.getViewName().contains("client_id=test-portal"));
    }

    @Test
    void post_signupDisabled_noClientId_redirectWithoutClientId() {
        when(tenantProperties.isSignUpEnabled()).thenReturn(false);

        UserDto dto = validUserDto();
        BindingResult br = new BeanPropertyBindingResult(dto, "userDto");
        RedirectAttributes ra = new RedirectAttributesModelMap();

        ModelAndView mav = controller.addSelfUser("ecsp", dto, br, signupRequest(null), ra);

        assertEquals(REDIRECT_LITERAL + "ecsp/" + SELF_SIGN_UP, mav.getViewName());
    }
}
