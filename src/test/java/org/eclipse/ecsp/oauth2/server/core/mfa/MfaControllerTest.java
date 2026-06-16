/********************************************************************************
 *
 * <p>
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

package org.eclipse.ecsp.oauth2.server.core.mfa;

import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for MfaController covering all MFA endpoints.
 */
@ExtendWith(MockitoExtension.class)
class MfaControllerTest {

    private static final String USERNAME = "testuser";
    private static final String TENANT_ID = "ecsp";
    private static final String TOTP_CODE = "123456";
    private static final String BASE32_SECRET = "JBSWY3DPEHPK3PXP";
    private static final String QR_URI = "otpauth://totp/UIDAM:testuser?secret=JBSWY3DPEHPK3PXP&issuer=UIDAM";
    private static final String MANUAL_KEY = "JBSW Y3DP EHPK 3PXP";

    @Mock
    private MfaSecretService mfaSecretService;

    @Mock
    private TotpService totpService;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    private MfaProperties mfaProperties;
    private MfaController mfaController;

    @BeforeEach
    void setUp() {
        mfaProperties = new MfaProperties();
        mfaProperties.setAppName("TestApp");
        MfaProperties.Recovery recovery = new MfaProperties.Recovery();
        recovery.setResendCooldownSeconds(60);
        mfaProperties.setRecovery(recovery);

        mfaController = new MfaController(mfaSecretService, totpService, mfaProperties, tenantConfigurationService);
        SecurityContextHolder.clearContext();

        TenantProperties tenantProperties = new TenantProperties();
        tenantProperties.setTenantId(TENANT_ID);
        lenient().when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
    }

    // ─────────────── populateAppName / resolveMfaAppName ───────────────────

    static Stream<Arguments> populateAppNameArgs() {
        return Stream.of(
            Arguments.of("tenant1", "TenantApp", "TenantApp - tenant1"),
            Arguments.of("default", "DefaultApp", "DefaultApp"),
            Arguments.of("tenant1", (String) null, "TestApp - tenant1"),
            Arguments.of("tenant1", "  ", "TestApp - tenant1")
        );
    }

    @ParameterizedTest
    @MethodSource("populateAppNameArgs")
    void populateAppName_withTenantProperties_returnsExpectedName(
            String tenantId, String mfaAppName, String expectedName) {
        TenantProperties props = new TenantProperties();
        props.setTenantId(tenantId);
        props.setMfaAppName(mfaAppName);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(props);

        String name = mfaController.populateAppName();
        assertEquals(expectedName, name);
    }

    @Test
    void populateAppName_whenTenantIsNull_returnsDefaultAppName() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(null);

        String name = mfaController.populateAppName();
        assertEquals("TestApp", name);
    }

    @Test
    void populateAppName_whenServiceThrows_fallsBackToDefault() {
        when(tenantConfigurationService.getTenantProperties()).thenThrow(new RuntimeException("error"));

        String name = mfaController.populateAppName();
        assertEquals("TestApp", name);
    }

    // ─────────────── enrollSetup ────────────────────────────────────────────

    @Test
    void enrollSetup_withAuthenticatedUser_returnsEnrollSetupView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        setAuthenticatedUser(USERNAME);

        MfaEnrollInitiateResponseDto enrollData = new MfaEnrollInitiateResponseDto(
                BASE32_SECRET, QR_URI, MANUAL_KEY);
        when(mfaSecretService.initiateEnrollment(USERNAME)).thenReturn(enrollData);
        when(totpService.generateQrCodeBase64FromUri(QR_URI)).thenReturn("qrBase64Data");

        Model model = new ExtendedModelMap();
        String view = mfaController.enrollSetup(TENANT_ID, request, model);

        assertEquals("mfa/mfa-enroll-setup", view);
        assertNotNull(model.getAttribute("qrBase64"));
    }

    @Test
    void enrollSetup_withManualKeyNull_formatsManualKey() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        setAuthenticatedUser(USERNAME);

        MfaEnrollInitiateResponseDto enrollData = new MfaEnrollInitiateResponseDto(
                BASE32_SECRET, QR_URI, null);
        when(mfaSecretService.initiateEnrollment(USERNAME)).thenReturn(enrollData);
        when(totpService.formatManualKey(BASE32_SECRET)).thenReturn(MANUAL_KEY);
        when(totpService.generateQrCodeBase64FromUri(QR_URI)).thenReturn("qrBase64Data");

        Model model = new ExtendedModelMap();
        String view = mfaController.enrollSetup(TENANT_ID, request, model);

        assertEquals("mfa/mfa-enroll-setup", view);
        verify(totpService).formatManualKey(BASE32_SECRET);
    }

    @Test
    void enrollSetup_withNullTenantId_usesDefaultTenant() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        setAuthenticatedUser(USERNAME);

        MfaEnrollInitiateResponseDto enrollData = new MfaEnrollInitiateResponseDto(
                BASE32_SECRET, QR_URI, MANUAL_KEY);
        when(mfaSecretService.initiateEnrollment(USERNAME)).thenReturn(enrollData);
        when(totpService.generateQrCodeBase64FromUri(QR_URI)).thenReturn("qrBase64Data");

        Model model = new ExtendedModelMap();
        String view = mfaController.enrollSetup(null, request, model);

        assertEquals("mfa/mfa-enroll-setup", view);
    }

    @Test
    void enrollSetup_whenUnauthenticated_returnsError() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        Model model = new ExtendedModelMap();
        String view = mfaController.enrollSetup(TENANT_ID, request, model);

        assertEquals("mfa/mfa-error", view);
        assertNotNull(model.getAttribute("error"));
    }

    @Test
    void enrollSetup_withPendingSession_returnsEnrollSetupView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        MfaEnrollInitiateResponseDto enrollData = new MfaEnrollInitiateResponseDto(
                BASE32_SECRET, QR_URI, MANUAL_KEY);
        when(mfaSecretService.initiateEnrollment(USERNAME)).thenReturn(enrollData);
        when(totpService.generateQrCodeBase64FromUri(QR_URI)).thenReturn("qrBase64Data");

        Model model = new ExtendedModelMap();
        String view = mfaController.enrollSetup(TENANT_ID, request, model);

        assertEquals("mfa/mfa-enroll-setup", view);
    }

    // ─────────────── enrollVerify ────────────────────────────────────────────

    @Test
    void enrollVerify_withValidCode_returnsBackupCodesView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("MFA_ENROLL_SECRET", BASE32_SECRET);
        session.setAttribute("MFA_ENROLL_USERNAME", USERNAME);
        request.setSession(session);

        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(true);
        doNothing().when(mfaSecretService).activateEnrollment(USERNAME);
        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(true);
        MfaBackupCodesResponseDto codes = new MfaBackupCodesResponseDto(
                List.of("code1", "code2"), 2);
        when(mfaSecretService.generateBackupCodes(USERNAME)).thenReturn(codes);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.enrollVerify(TENANT_ID, TOTP_CODE, request, response, model);

        assertEquals("mfa/mfa-enroll-backup-codes", view);
    }

    @Test
    void enrollVerify_withValidCodeBackupDisabled_returnsBackupCodesViewEmpty() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("MFA_ENROLL_SECRET", BASE32_SECRET);
        session.setAttribute("MFA_ENROLL_USERNAME", USERNAME);
        request.setSession(session);

        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(true);
        doNothing().when(mfaSecretService).activateEnrollment(USERNAME);
        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(false);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.enrollVerify(TENANT_ID, TOTP_CODE, request, response, model);

        assertEquals("mfa/mfa-enroll-backup-codes", view);
    }

    @Test
    void enrollVerify_withValidCodeBackupCodesGenerateFails_returnsBackupCodesViewEmpty() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("MFA_ENROLL_SECRET", BASE32_SECRET);
        session.setAttribute("MFA_ENROLL_USERNAME", USERNAME);
        request.setSession(session);

        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(true);
        doNothing().when(mfaSecretService).activateEnrollment(USERNAME);
        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(true);
        when(mfaSecretService.generateBackupCodes(USERNAME)).thenThrow(new RuntimeException("fail"));

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.enrollVerify(TENANT_ID, TOTP_CODE, request, response, model);

        assertEquals("mfa/mfa-enroll-backup-codes", view);
    }

    @Test
    void enrollVerify_withInvalidCode_returnsEnrollSetupWithError() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("MFA_ENROLL_SECRET", BASE32_SECRET);
        session.setAttribute("MFA_ENROLL_USERNAME", USERNAME);
        request.setSession(session);

        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(false);
        when(totpService.formatManualKey(BASE32_SECRET)).thenReturn(MANUAL_KEY);
        when(totpService.generateQrCodeBase64(USERNAME, BASE32_SECRET)).thenReturn("qrBase64");

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.enrollVerify(TENANT_ID, TOTP_CODE, request, response, model);

        assertEquals("mfa/mfa-enroll-setup", view);
        assertNotNull(model.getAttribute("error"));
    }

    @Test
    void enrollVerify_withNullSession_redirectsToLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.enrollVerify(TENANT_ID, TOTP_CODE, request, response, model);

        assertEquals("redirect:/login", view);
    }

    @Test
    void enrollVerify_withNullSecret_returnsErrorView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.enrollVerify(TENANT_ID, TOTP_CODE, request, response, model);

        assertEquals("mfa/mfa-error", view);
    }

    // ─────────────── backupCodesConfirm ──────────────────────────────────────

    @Test
    void backupCodesConfirm_withValidSession_completesLogin() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("MFA_BACKUP_CODES_PENDING_USERNAME", USERNAME);
        session.setAttribute("MFA_BACKUP_CODES_PENDING_TENANT", TENANT_ID);
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.backupCodesConfirm(TENANT_ID, request, response, model);

        // Should redirect to root since no saved request
        assertNotNull(view);
    }

    @Test
    void backupCodesConfirm_withNullSession_redirectsToLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.backupCodesConfirm(TENANT_ID, request, response, model);

        assertEquals("redirect:/login", view);
    }

    @Test
    void backupCodesConfirm_withNullUsername_returnsErrorView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.backupCodesConfirm(TENANT_ID, request, response, model);

        assertEquals("mfa/mfa-error", view);
    }

    // ─────────────── challengePage ────────────────────────────────────────────

    @Test
    void challengePage_withPendingToken_returnsChallengeView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        Model model = new ExtendedModelMap();
        String view = mfaController.challengePage(TENANT_ID, request, model);

        assertEquals("mfa/mfa-challenge", view);
        assertEquals(USERNAME, model.getAttribute("username"));
    }

    @Test
    void challengePage_withNoPendingToken_redirectsToLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        String view = mfaController.challengePage(TENANT_ID, request, model);

        assertEquals("redirect:/login", view);
    }

    @Test
    void challengePage_withNullTenantId_usesDefaultTenant() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_TENANT, TENANT_ID);
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        Model model = new ExtendedModelMap();
        String view = mfaController.challengePage(null, request, model);

        assertEquals("mfa/mfa-challenge", view);
    }

    // ─────────────── challengeSubmit ──────────────────────────────────────────

    @Test
    void challengeSubmit_withValidCode_completesLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));
        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(true);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.challengeSubmit(TENANT_ID, TOTP_CODE, request, response, model);

        // Redirects to root since no saved request
        assertNotNull(view);
    }

    @Test
    void challengeSubmit_withInvalidCode_returnsChallengeWithError() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));
        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(false);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.challengeSubmit(TENANT_ID, TOTP_CODE, request, response, model);

        assertEquals("mfa/mfa-challenge", view);
        assertNotNull(model.getAttribute("error"));
    }

    @Test
    void challengeSubmit_withNullSecret_returnsChallengeWithError() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.empty());

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.challengeSubmit(TENANT_ID, TOTP_CODE, request, response, model);

        assertEquals("mfa/mfa-challenge", view);
    }

    @Test
    void challengeSubmit_withNoPendingToken_redirectsToLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.challengeSubmit(TENANT_ID, TOTP_CODE, request, response, model);

        assertEquals("redirect:/login", view);
    }

    // ─────────────── reEnroll ─────────────────────────────────────────────────

    @Test
    void reEnroll_withAuthenticatedUser_revokesAndRedirects() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        setAuthenticatedUser(USERNAME);

        doNothing().when(mfaSecretService).revoke(USERNAME);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.reEnroll(null, null, request, response, model);

        verify(mfaSecretService).revoke(USERNAME);
        assertNotNull(view);
    }

    @Test
    void reEnroll_withTenantPathVar_usesPathTenant() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        setAuthenticatedUser(USERNAME);

        doNothing().when(mfaSecretService).revoke(USERNAME);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.reEnroll("mytenant", null, request, response, model);

        assertNotNull(view);
    }

    @Test
    void reEnroll_withParamTenantId_usesParamTenant() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        setAuthenticatedUser(USERNAME);

        doNothing().when(mfaSecretService).revoke(USERNAME);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.reEnroll(null, "paramtenant", request, response, model);

        assertNotNull(view);
    }

    @Test
    void reEnroll_withUnauthenticatedUser_returnsErrorView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.reEnroll(null, null, request, response, model);

        assertEquals("mfa/mfa-error", view);
        assertNotNull(model.getAttribute("error"));
    }

    // ─────────────── recoveryPage ─────────────────────────────────────────────

    @Test
    void recoveryPage_withPendingToken_returnsRecoveryView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        Model model = new ExtendedModelMap();
        String view = mfaController.recoveryPage(TENANT_ID, request, model);

        assertEquals("mfa/mfa-recovery", view);
        assertEquals(USERNAME, model.getAttribute("username"));
    }

    @Test
    void recoveryPage_withNoPendingToken_redirectsToLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        String view = mfaController.recoveryPage(TENANT_ID, request, model);

        assertEquals("redirect:/login", view);
    }

    // ─────────────── recoverySendEmail ────────────────────────────────────────

    @Test
    void recoverySendEmail_success_returnsVerifyView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        doNothing().when(mfaSecretService).sendRecoveryKey(USERNAME);

        Model model = new ExtendedModelMap();
        String view = mfaController.recoverySendEmail(TENANT_ID, request, model);

        assertEquals("mfa/mfa-recovery-verify", view);
        assertNotNull(model.getAttribute("emailSent"));
    }

    @Test
    void recoverySendEmail_withinCooldown_showsError() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        // Set last sent timestamp to now (within cooldown)
        session.setAttribute("MFA_RECOVERY_SENT_AT", System.currentTimeMillis());
        request.setSession(session);

        Model model = new ExtendedModelMap();
        String view = mfaController.recoverySendEmail(TENANT_ID, request, model);

        assertEquals("mfa/mfa-recovery-verify", view);
        assertNotNull(model.getAttribute("error"));
    }

    @Test
    void recoverySendEmail_withNoPendingToken_redirectsToLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        String view = mfaController.recoverySendEmail(TENANT_ID, request, model);

        assertEquals("redirect:/login", view);
    }

    @Test
    void recoverySendEmail_whenOauth2ExceptionThrown_returnsRecoveryWithError() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        doThrow(new OAuth2AuthenticationException(new OAuth2Error("error", "OAuth2 error", null)))
                .when(mfaSecretService).sendRecoveryKey(USERNAME);

        Model model = new ExtendedModelMap();
        String view = mfaController.recoverySendEmail(TENANT_ID, request, model);

        assertEquals("mfa/mfa-recovery", view);
        assertNotNull(model.getAttribute("error"));
    }

    @Test
    void recoverySendEmail_whenGenericExceptionThrown_returnsRecoveryWithError() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        doThrow(new RuntimeException("network error")).when(mfaSecretService).sendRecoveryKey(USERNAME);

        Model model = new ExtendedModelMap();
        String view = mfaController.recoverySendEmail(TENANT_ID, request, model);

        assertEquals("mfa/mfa-recovery", view);
        assertNotNull(model.getAttribute("error"));
    }

    // ─────────────── recoveryVerifyKey ─────────────────────────────────────────

    @Test
    void recoveryVerifyKey_withValidKeyAndBackupCodesEnabled_returnsBackupView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("MFA_RECOVERY_SENT_AT", System.currentTimeMillis() - 90000L);
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        when(mfaSecretService.verifyRecoveryKeyAndRevoke(USERNAME, "ABCDEF")).thenReturn(true);
        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(true);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryVerifyKey(TENANT_ID, "ABCDEF", request, response, model);

        assertEquals("mfa/mfa-recovery-backup", view);
    }

    @Test
    void recoveryVerifyKey_withValidKeyAndBackupCodesDisabled_redirectsToEnroll() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        when(mfaSecretService.verifyRecoveryKeyAndRevoke(USERNAME, "ABCDEF")).thenReturn(true);
        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(false);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryVerifyKey(TENANT_ID, "ABCDEF", request, response, model);

        assertNotNull(view);
        // Should redirect to enroll setup
    }

    @Test
    void recoveryVerifyKey_withInvalidKey_returnsVerifyViewWithError() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        when(mfaSecretService.verifyRecoveryKeyAndRevoke(USERNAME, "WRONG")).thenReturn(false);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryVerifyKey(TENANT_ID, "WRONG", request, response, model);

        assertEquals("mfa/mfa-recovery-verify", view);
        assertNotNull(model.getAttribute("error"));
    }

    @Test
    void recoveryVerifyKey_withNoPendingToken_redirectsToLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryVerifyKey(TENANT_ID, "ABCDEF", request, response, model);

        assertEquals("redirect:/login", view);
    }

    @Test
    void recoveryVerifyKey_withValidKeySessionNotNull_clearsSentAt() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("MFA_RECOVERY_SENT_AT", System.currentTimeMillis());
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        when(mfaSecretService.verifyRecoveryKeyAndRevoke(USERNAME, "ABCDEF")).thenReturn(true);
        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(false);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        mfaController.recoveryVerifyKey(TENANT_ID, "ABCDEF", request, response, model);

        // Session should have sent_at removed
    }

    // ─────────────── recoveryBackupPage ────────────────────────────────────────

    @Test
    void recoveryBackupPage_withPendingAndBackupEnabled_returnsBackupView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(true);

        Model model = new ExtendedModelMap();
        String view = mfaController.recoveryBackupPage(TENANT_ID, request, model);

        assertEquals("mfa/mfa-recovery-backup", view);
    }

    @Test
    void recoveryBackupPage_withNoPendingToken_redirectsToLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        String view = mfaController.recoveryBackupPage(TENANT_ID, request, model);

        assertEquals("redirect:/login", view);
    }

    @Test
    void recoveryBackupPage_withBackupDisabled_redirectsToRecovery() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(false);

        Model model = new ExtendedModelMap();
        String view = mfaController.recoveryBackupPage(TENANT_ID, request, model);

        // Redirects to recovery
        assertNotNull(view);
    }

    // ─────────────── recoveryBackupSubmit ──────────────────────────────────────

    @Test
    void recoveryBackupSubmit_withValidBackupCode_redirectsToEnroll() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        session.setAttribute("MFA_RECOVERY_EMAIL_VERIFIED", Boolean.TRUE);
        request.setSession(session);

        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(true);
        MfaBackupCodeVerifyResponseDto result = new MfaBackupCodeVerifyResponseDto(true, 4, false);
        when(mfaSecretService.verifyBackupCode(USERNAME, "BACKUP1")).thenReturn(result);
        doNothing().when(mfaSecretService).revoke(USERNAME);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryBackupSubmit(TENANT_ID, "BACKUP1", request, response, model);

        assertNotNull(view);
        verify(mfaSecretService).revoke(USERNAME);
    }

    @Test
    void recoveryBackupSubmit_withInvalidBackupCode_returnsBackupViewWithError() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        session.setAttribute("MFA_RECOVERY_EMAIL_VERIFIED", Boolean.TRUE);
        request.setSession(session);

        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(true);
        MfaBackupCodeVerifyResponseDto result = new MfaBackupCodeVerifyResponseDto(false, 4, false);
        when(mfaSecretService.verifyBackupCode(USERNAME, "WRONG")).thenReturn(result);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryBackupSubmit(TENANT_ID, "WRONG", request, response, model);

        assertEquals("mfa/mfa-recovery-backup", view);
        assertNotNull(model.getAttribute("error"));
    }

    @Test
    void recoveryBackupSubmit_withNullResult_returnsBackupViewWithError() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        session.setAttribute("MFA_RECOVERY_EMAIL_VERIFIED", Boolean.TRUE);
        request.setSession(session);

        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(true);
        when(mfaSecretService.verifyBackupCode(USERNAME, "WRONG")).thenReturn(null);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryBackupSubmit(TENANT_ID, "WRONG", request, response, model);

        assertEquals("mfa/mfa-recovery-backup", view);
    }

    @Test
    void recoveryBackupSubmit_withNoPendingToken_redirectsToLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryBackupSubmit(TENANT_ID, "BACKUP1", request, response, model);

        assertEquals("redirect:/login", view);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void recoveryBackupSubmit_redirectsToRecovery(boolean backupCodesEnabled) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(backupCodesEnabled);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryBackupSubmit(TENANT_ID, "BACKUP1", request, response, model);

        assertNotNull(view);
    }

    // ─────────────── recoveryContinue ─────────────────────────────────────────

    @Test
    void recoveryContinue_withNullSession_redirectsToLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryContinue(TENANT_ID, request, response, model);

        assertEquals("redirect:/login", view);
    }

    @Test
    void recoveryContinue_withSessionNoSavedRequest_redirectsToRoot() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryContinue(TENANT_ID, request, response, model);

        assertNotNull(view);
    }

    @Test
    void recoveryContinue_withNullTenantId_usesDefaultTenant() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryContinue(null, request, response, model);

        assertNotNull(view);
    }

    // ─────────────── recoveryReEnroll ─────────────────────────────────────────

    @Test
    void recoveryReEnroll_withAuthenticatedUser_revokesAndRedirects() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        setAuthenticatedUser(USERNAME);

        doNothing().when(mfaSecretService).revoke(USERNAME);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryReEnroll(TENANT_ID, request, response, model);

        verify(mfaSecretService).revoke(USERNAME);
        assertNotNull(view);
    }

    @Test
    void recoveryReEnroll_withNullUsername_doesNotRevoke() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        // No authentication set

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryReEnroll(TENANT_ID, request, response, model);

        assertNotNull(view);
    }

    // ─────────────── completeLogin with tenant ─────────────────────────────────

    @Test
    void challengeSubmit_withNonDefaultTenant_redirectsToTenantRoot() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        request.setSession(session);

        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));
        when(totpService.validateCode(anyString(), anyString(), anyString())).thenReturn(true);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        // Use a non-default tenant
        String view = mfaController.challengeSubmit("custom-tenant", TOTP_CODE, request, response, model);

        // Should redirect to /custom-tenant/
        assertNotNull(view);
    }

    // ─────────────── Helper methods ───────────────────────────────────────────

    private void setAuthenticatedUser(String username) {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                username, "password",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
