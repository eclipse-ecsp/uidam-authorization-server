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

package org.eclipse.ecsp.oauth2.server.core.service;

import org.eclipse.ecsp.oauth2.server.core.client.AuthManagementClient;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.SignupClientConfig;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.SignupProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.response.dto.UserAttributeDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SignupAttributeService}.
 * Covers: setupSignupAttributes, validateCustomAttributeKeys, and the
 * resolveCustomAttributeKeys exclusion logic.
 */
class SignupAttributeServiceTest {

    @Mock
    private UserManagementClient userManagementClient;

    @Mock
    private AuthManagementClient authManagementClient;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private TenantProperties tenantProperties;

    private SignupAttributeService service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getSignupConfigList()).thenReturn(Collections.emptyList());
        // Feature defaults to false in production; explicitly enable it for these tests.
        SignupProperties enabledSignup = new SignupProperties();
        enabledSignup.setAdditionalAttributesEnabled(true);
        when(tenantProperties.getSignup()).thenReturn(enabledSignup);
        service = new SignupAttributeService(userManagementClient, authManagementClient,
                tenantConfigurationService);
    }

    // -----------------------------------------------------------------------
    // Helper builders
    // -----------------------------------------------------------------------

    private UserAttributeDto attr(String name, Boolean dynamic) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setName(name);
        dto.setDynamicAttribute(dynamic);
        dto.setMandatory(true);
        dto.setType("varchar");
        return dto;
    }

    private SignupClientConfig config(String clientId, String skip, String customMap, String status) {
        SignupClientConfig cfg = new SignupClientConfig();
        cfg.setClientId(clientId);
        cfg.setSkipAttributes(skip);
        cfg.setCustomAttributeListMap(customMap);
        cfg.setUserStatus(status);
        return cfg;
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – feature flag disabled → skip everything
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_featureDisabled_skipsAllAndDisablesSection() {
        SignupProperties disabledSignup = new SignupProperties();
        disabledSignup.setAdditionalAttributesEnabled(false);
        when(tenantProperties.getSignup()).thenReturn(disabledSignup);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        assertFalse((Boolean) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED));
        assertTrue(((List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES)).isEmpty());
        verify(userManagementClient, never()).getUserAttributes();
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – blank clientId
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_blankClientId_disablesSection() {
        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, null);

        assertFalse((Boolean) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED));
        assertTrue(((List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES)).isEmpty());
        verify(userManagementClient, never()).getUserAttributes();
    }

    @Test
    void setupSignupAttributes_emptyClientId_disablesSection() {
        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "");

        assertFalse((Boolean) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED));
        verify(userManagementClient, never()).getUserAttributes();
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – valid client_id with no signup-config-list entry
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_clientNotConfigured_showsNoAttributes() {
        // tenantProperties.getSignupClientConfig("device-mgmt") is unstubbed -> returns null,
        // mirroring a real, registered client that simply has no signup-config-list entry.
        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "device-mgmt");

        assertFalse((Boolean) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED));
        assertTrue(((List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES)).isEmpty());
        verify(userManagementClient, never()).getUserAttributes();
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – user-management returns null
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_nullFromUserManagement_setsEmptyList() {
        when(userManagementClient.getUserAttributes()).thenReturn(null);
        SignupClientConfig cfg = config("test-portal", null, null, null);
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> attrs = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertTrue(attrs.isEmpty());
        assertFalse((Boolean) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED));
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – happy path, no exclusions
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_noExclusions_allAttributesShown() {
        List<UserAttributeDto> fetched = List.of(attr("nickName", false), attr("age", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        when(userManagementClient.getAllUserAttributes()).thenReturn(fetched);
        SignupClientConfig cfg = config("test-portal", null, null, null);
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> attrs = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertEquals(2, attrs.size());
        assertTrue((Boolean) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED));
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – customAttributeListMap keys excluded from form
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_customAttrKeys_excludedFromForm() {
        List<UserAttributeDto> fetched = List.of(
                attr("nickName", false),
                attr("custom:companyName", false),
                attr("custom:companyAddress", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        when(userManagementClient.getAllUserAttributes()).thenReturn(fetched);

        SignupClientConfig cfg = config("test-portal", null,
                "custom:companyName#Acme,custom:companyAddress#123 Main", null);
        when(tenantProperties.getSignupConfigList()).thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> shown = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertEquals(1, shown.size());
        assertEquals("nickName", ((UserAttributeDto) shown.get(0)).getName());
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – skipAttributes exclusions
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_skipAttributes_excludedFromForm() {
        List<UserAttributeDto> fetched = List.of(
                attr("nickName", false),
                attr("hasValidPassport", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        when(userManagementClient.getAllUserAttributes()).thenReturn(Collections.emptyList());

        SignupClientConfig cfg = config("test-portal", "hasValidPassport", null, null);
        when(tenantProperties.getSignupConfigList()).thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> shown = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertEquals(1, shown.size());
        assertEquals("nickName", ((UserAttributeDto) shown.get(0)).getName());
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – all attributes excluded → section disabled
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_allAttributesExcluded_sectionDisabled() {
        List<UserAttributeDto> fetched = List.of(attr("custom:companyName", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        when(userManagementClient.getAllUserAttributes()).thenReturn(fetched);

        SignupClientConfig cfg = config("test-portal", null, "custom:companyName#Acme", null);
        when(tenantProperties.getSignupConfigList()).thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        assertFalse((Boolean) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED));
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – exception from user-management → empty list
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_userManagementThrows_returnsEmptyList() {
        when(userManagementClient.getUserAttributes()).thenThrow(new RuntimeException("network error"));
        SignupClientConfig cfg = config("test-portal", null, null, null);
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> attrs = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertTrue(attrs.isEmpty());
        assertFalse((Boolean) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED));
    }

    // -----------------------------------------------------------------------
    // validateCustomAttributeKeys – empty customAttributeListMap → no-op
    // -----------------------------------------------------------------------

    @Test
    void validateCustomAttributeKeys_emptyMap_noOp() {
        SignupClientConfig cfg = config("test-portal", null, "", null);
        when(tenantProperties.getSignupConfigList()).thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        // Should not throw and should not call getAllUserAttributes
        service.validateCustomAttributeKeys("test-portal");
        verify(userManagementClient, never()).getAllUserAttributes();
    }

    @Test
    void validateCustomAttributeKeys_noConfigForClient_noOp() {
        // No config entry for the client
        service.validateCustomAttributeKeys("unknown-portal");
        verify(userManagementClient, never()).getAllUserAttributes();
    }

    // -----------------------------------------------------------------------
    // validateCustomAttributeKeys – all keys known → passes
    // -----------------------------------------------------------------------

    @Test
    void validateCustomAttributeKeys_allKeysKnown_noException() {
        SignupClientConfig cfg = config("test-portal", null,
                "custom:companyName#Acme,custom:companyAddress#123", null);
        when(tenantProperties.getSignupConfigList()).thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        List<UserAttributeDto> allAttrs = List.of(
                attr("custom:companyName", true),
                attr("custom:companyAddress", true));
        when(userManagementClient.getAllUserAttributes()).thenReturn(allAttrs);

        // Must not throw
        service.validateCustomAttributeKeys("test-portal");
    }

    // -----------------------------------------------------------------------
    // validateCustomAttributeKeys – one unknown key → throws
    // -----------------------------------------------------------------------

    @Test
    void validateCustomAttributeKeys_unknownKey_throwsIllegalStateException() {
        SignupClientConfig cfg = config("test-portal", null,
                "custom:companyName#Acme,custom:unknownAttr#value", null);
        when(tenantProperties.getSignupConfigList()).thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        List<UserAttributeDto> allAttrs = List.of(attr("custom:companyName", true));
        when(userManagementClient.getAllUserAttributes()).thenReturn(allAttrs);

        assertThrows(IllegalStateException.class,
                () -> service.validateCustomAttributeKeys("test-portal"));
    }

    @Test
    void validateCustomAttributeKeys_allKeysUnknown_throwsIllegalStateException() {
        SignupClientConfig cfg = config("test-portal", null, "badKey#value", null);
        when(tenantProperties.getSignupConfigList()).thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(userManagementClient.getAllUserAttributes()).thenReturn(Collections.emptyList());

        assertThrows(IllegalStateException.class,
                () -> service.validateCustomAttributeKeys("test-portal"));
    }

    // -----------------------------------------------------------------------
    // validateCustomAttributeKeys – getAllUserAttributes returns null → skip
    // -----------------------------------------------------------------------

    @Test
    void validateCustomAttributeKeys_userManagementReturnsNull_skipsValidation() {
        SignupClientConfig cfg = config("test-portal", null, "custom:companyName#Acme", null);
        when(tenantProperties.getSignupConfigList()).thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(userManagementClient.getAllUserAttributes()).thenReturn(null);

        // Should not throw when user-management is unavailable
        service.validateCustomAttributeKeys("test-portal");
    }

    // -----------------------------------------------------------------------
    // validateCustomAttributeKeys – case-insensitive key comparison
    // -----------------------------------------------------------------------

    @Test
    void validateCustomAttributeKeys_caseInsensitiveMatch_passes() {
        SignupClientConfig cfg = config("test-portal", null, "CUSTOM:CompanyName#Acme", null);
        when(tenantProperties.getSignupConfigList()).thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        List<UserAttributeDto> allAttrs = List.of(attr("custom:companyname", true));
        when(userManagementClient.getAllUserAttributes()).thenReturn(allAttrs);

        // Should not throw
        service.validateCustomAttributeKeys("test-portal");
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – clientId case-insensitive config lookup
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_clientIdCaseInsensitive_matchesConfig() {
        List<UserAttributeDto> fetched = List.of(
                attr("nickName", false),
                attr("custom:companyName", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        when(userManagementClient.getAllUserAttributes()).thenReturn(fetched);

        SignupClientConfig cfg = config("TEST-PORTAL", null, "custom:companyName#Acme", null);
        when(tenantProperties.getSignupConfigList()).thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal"); // lower-case match

        List<?> shown = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertEquals(1, shown.size());
        assertEquals("nickName", ((UserAttributeDto) shown.get(0)).getName());
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – multiple exclusion sources combined
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_skipAndCustomMap_bothExcluded() {
        List<UserAttributeDto> fetched = new ArrayList<>();
        fetched.add(attr("nickName", false));
        fetched.add(attr("hasValidPassport", false));
        fetched.add(attr("custom:companyName", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        when(userManagementClient.getAllUserAttributes()).thenReturn(fetched);

        SignupClientConfig cfg = config("test-portal",
                "hasValidPassport",
                "custom:companyName#Acme",
                null);
        when(tenantProperties.getSignupConfigList()).thenReturn(List.of(cfg));
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> shown = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertEquals(1, shown.size());
        assertEquals("nickName", ((UserAttributeDto) shown.get(0)).getName());
    }

    // -----------------------------------------------------------------------
    // setupSignupAttributes – empty attribute list from user-management
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_emptyAttrList_sectionDisabled() {
        when(userManagementClient.getUserAttributes()).thenReturn(Collections.emptyList());
        when(userManagementClient.getAllUserAttributes()).thenReturn(Collections.emptyList());
        SignupClientConfig cfg = config("test-portal", null, null, null);
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        assertFalse((Boolean) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES_ENABLED));
    }

    // -----------------------------------------------------------------------
    // warnOnUnknownCustomAttributeKeys (via setupSignupAttributes) – getAllUserAttributes throws
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_warnCheckThrows_stillReturnsAttributes() {
        List<UserAttributeDto> fetched = List.of(attr("nickName", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        // warnOnUnknownCustomAttributeKeys is the sole caller of getAllUserAttributes here; it must throw.
        when(userManagementClient.getAllUserAttributes())
                .thenThrow(new RuntimeException("network error"));
        SignupClientConfig cfg = config("test-portal", null, "custom:companyName#Acme", null);
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> shown = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertEquals(1, shown.size());
    }

    // -----------------------------------------------------------------------
    // warnOnUnknownCustomAttributeKeys – getAllUserAttributes returns null on the warn check
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_warnCheckReturnsNull_stillReturnsAttributes() {
        List<UserAttributeDto> fetched = List.of(attr("nickName", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        // warnOnUnknownCustomAttributeKeys is the sole caller of getAllUserAttributes here; it returns null.
        when(userManagementClient.getAllUserAttributes()).thenReturn(null);
        SignupClientConfig cfg = config("test-portal", null, "custom:companyName#Acme", null);
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> shown = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertEquals(1, shown.size());
    }

    // -----------------------------------------------------------------------
    // warnOnUnknownCustomAttributeKeys – key not found in user_attributes logs a mismatch warning
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_warnCheckKeyMismatch_stillReturnsAttributes() {
        List<UserAttributeDto> fetched = List.of(attr("nickName", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        // custom:companyName is never present in the "all attributes" list -> triggers mismatch warning.
        when(userManagementClient.getAllUserAttributes()).thenReturn(Collections.emptyList());
        SignupClientConfig cfg = config("test-portal", null, "custom:companyName#Acme", null);
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> shown = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertEquals(1, shown.size());
    }

    // -----------------------------------------------------------------------
    // resolveSkipList / resolveCustomAttributeKeys – getSignupClientConfig throws after the
    // initial null-check, exercising both catch blocks.
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_signupClientConfigThrowsDuringResolution_fallsBackGracefully() {
        List<UserAttributeDto> fetched = List.of(attr("nickName", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        when(userManagementClient.getAllUserAttributes()).thenReturn(fetched);
        SignupClientConfig cfg = config("test-portal", null, null, null);
        when(tenantProperties.getSignupClientConfig("test-portal"))
                .thenReturn(cfg)
                .thenThrow(new RuntimeException("config lookup failed"));

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> shown = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertEquals(1, shown.size());
    }

    // -----------------------------------------------------------------------
    // resolveSkipList Source 2 – DB-based skip list parsed from additionalInformation JSON
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_dbSkipList_excludesAttribute() {
        List<UserAttributeDto> fetched = List.of(attr("nickName", false), attr("hasValidPassport", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        when(userManagementClient.getAllUserAttributes()).thenReturn(fetched);
        SignupClientConfig cfg = config("test-portal", null, null, null);
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);

        org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails clientDetails =
                new org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails();
        clientDetails.setAdditionalInformation("{\"signupSkipAttributes\":[\"hasValidPassport\"]}");
        when(authManagementClient.getClientDetails("test-portal")).thenReturn(clientDetails);

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> shown = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertEquals(1, shown.size());
        assertEquals("nickName", ((UserAttributeDto) shown.get(0)).getName());
    }

    // -----------------------------------------------------------------------
    // resolveSkipList Source 2 – authManagementClient throws, falls back gracefully
    // -----------------------------------------------------------------------

    @Test
    void setupSignupAttributes_authManagementClientThrows_fallsBackGracefully() {
        List<UserAttributeDto> fetched = List.of(attr("nickName", false));
        when(userManagementClient.getUserAttributes()).thenReturn(fetched);
        when(userManagementClient.getAllUserAttributes()).thenReturn(fetched);
        SignupClientConfig cfg = config("test-portal", null, null, null);
        when(tenantProperties.getSignupClientConfig("test-portal")).thenReturn(cfg);
        when(authManagementClient.getClientDetails("test-portal"))
                .thenThrow(new RuntimeException("auth-mgmt unavailable"));

        Model model = new ExtendedModelMap();
        service.setupSignupAttributes(model, "test-portal");

        List<?> shown = (List<?>) model.asMap().get(SignupAttributeService.SIGNUP_ADDITIONAL_ATTRIBUTES);
        assertEquals(1, shown.size());
        assertEquals("nickName", ((UserAttributeDto) shown.get(0)).getName());
    }
}
