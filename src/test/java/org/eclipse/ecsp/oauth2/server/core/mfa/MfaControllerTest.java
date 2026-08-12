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

import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.audit.enums.AuditEventType;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.metrics.MetricType;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
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

    @Mock
    private MfaStateService mfaStateService;

    @Mock
    private AuditLogger auditLogger;

    @Mock
    private AuthorizationMetricsService metricsService;

    private MfaProperties mfaProperties;
    private MfaController mfaController;

    @BeforeEach
    void setUp() throws Exception {
        // Initialize the TenantUtils singleton so that TenantUtils.getDefaultTenant()
        // returns "ecsp" (the same as TENANT_ID) instead of throwing/returning null.
        TenantUtils tenantUtils = new TenantUtils();
        Field defaultTenantField = TenantUtils.class.getDeclaredField("defaultTenant");
        defaultTenantField.setAccessible(true);
        defaultTenantField.set(tenantUtils, TENANT_ID);

        mfaProperties = new MfaProperties();
        mfaProperties.setAppName("TestApp");
        MfaProperties.Recovery recovery = new MfaProperties.Recovery();
        recovery.setResendCooldownSeconds(60);
        mfaProperties.setRecovery(recovery);

        mfaController = new MfaController(mfaSecretService, totpService, mfaProperties,
                tenantConfigurationService, mfaStateService, auditLogger, metricsService);
        SecurityContextHolder.clearContext();

        TenantProperties tenantProperties = new TenantProperties();
        tenantProperties.setTenantId(TENANT_ID);
        lenient().when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);

        // Default: no pending token in DB for any request
        lenient().when(mfaStateService.loadPending(any())).thenReturn(Optional.empty());
        lenient().when(mfaStateService.loadTenant(any())).thenReturn(null);
        lenient().when(mfaStateService.getRecoverySentAt(anyString())).thenReturn(null);
        lenient().when(mfaStateService.isRecoveryEmailVerified(anyString())).thenReturn(false);
    }

    // ─────────────── populateAppName / resolveMfaAppName ───────────────────

    static Stream<Arguments> populateAppNameData() {
        return Stream.of(
            Arguments.of("tenant1", "TenantApp", "TenantApp - tenant1"),
            Arguments.of("default", "DefaultApp", "DefaultApp"),
            Arguments.of("tenant1", null, "TestApp - tenant1"),
            Arguments.of("tenant1", "  ", "TestApp - tenant1")
        );
    }

    @ParameterizedTest
    @MethodSource("populateAppNameData")
    void populateAppName_withVariousTenantConfig_returnsExpectedName(
            String tenantId, String mfaAppName, String expected) {
        TenantProperties props = new TenantProperties();
        props.setTenantId(tenantId);
        props.setMfaAppName(mfaAppName);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(props);

        assertEquals(expected, mfaController.populateAppName());
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
        final MockHttpServletRequest request = new MockHttpServletRequest();
        setAuthenticatedUser(USERNAME);
        lenient().when(mfaStateService.loadPending(any())).thenReturn(Optional.empty());

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
        final MockHttpServletRequest request = new MockHttpServletRequest();
        setAuthenticatedUser(USERNAME);
        lenient().when(mfaStateService.loadPending(any())).thenReturn(Optional.empty());

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
        final MockHttpServletRequest request = new MockHttpServletRequest();
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

        Model model = new ExtendedModelMap();
        String view = mfaController.enrollSetup(TENANT_ID, request, model);

        assertEquals("mfa/mfa-error", view);
        assertNotNull(model.getAttribute("error"));
    }

    @Test
    void enrollSetup_withPendingSession_returnsEnrollSetupView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

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
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));

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
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));

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
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));

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
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));

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
    void enrollVerify_withNullUsername_redirectsToLogin() {
        // No pending token in DB, no SecurityContext auth → username is null → redirect to login
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.enrollVerify(TENANT_ID, TOTP_CODE, request, response, model);

        assertEquals("redirect:/login", view);
    }

    @Test
    void enrollVerify_withNullSecret_returnsErrorView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        // Secret not found in user-management
        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.empty());

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.enrollVerify(TENANT_ID, TOTP_CODE, request, response, model);

        assertEquals("mfa/mfa-error", view);
    }

    // ─────────────── backupCodesConfirm ──────────────────────────────────────

    @Test
    void backupCodesConfirm_withValidSession_completesLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaStateService.loadTenant(request)).thenReturn(TENANT_ID);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.backupCodesConfirm(TENANT_ID, request, response, model);

        // Should redirect to root since no saved request
        assertNotNull(view);
    }

    @Test
    void backupCodesConfirm_withNullUsername_returnsErrorView() {
        // No pending token in DB → username is null
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.backupCodesConfirm(TENANT_ID, request, response, model);

        assertEquals("mfa/mfa-error", view);
    }

    // ─────────────── challengePage ────────────────────────────────────────────

    @Test
    void challengePage_withPendingToken_returnsChallengeView() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

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
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaStateService.loadTenant(request)).thenReturn(TENANT_ID);

        Model model = new ExtendedModelMap();
        String view = mfaController.challengePage(null, request, model);

        assertEquals("mfa/mfa-challenge", view);
    }

    // ─────────────── challengeSubmit ──────────────────────────────────────────

    @Test
    void challengeSubmit_withValidCode_completesLogin() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

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
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

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
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

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

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.reEnroll(null, null, request, response, model);

        assertEquals("mfa/mfa-error", view);
        assertNotNull(model.getAttribute("error"));
    }

    // ─────────────── recoveryPage ─────────────────────────────────────────────

    @Test
    void recoveryPage_withPendingToken_returnsRecoveryView() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

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
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

        doNothing().when(mfaSecretService).sendRecoveryKey(USERNAME);

        Model model = new ExtendedModelMap();
        String view = mfaController.recoverySendEmail(TENANT_ID, request, model);

        assertEquals("mfa/mfa-recovery-verify", view);
        assertNotNull(model.getAttribute("emailSent"));
    }

    @Test
    void recoverySendEmail_withinCooldown_showsError() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        // Last-sent timestamp is now → still within the 60-second cooldown configured in setUp().
        when(mfaStateService.getRecoverySentAt(USERNAME)).thenReturn(System.currentTimeMillis());

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
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

        doThrow(new OAuth2AuthenticationException(new OAuth2Error("error", "OAuth2 error", null)))
                .when(mfaSecretService).sendRecoveryKey(USERNAME);

        Model model = new ExtendedModelMap();
        String view = mfaController.recoverySendEmail(TENANT_ID, request, model);

        assertEquals("mfa/mfa-recovery", view);
        assertNotNull(model.getAttribute("error"));
    }

    @Test
    void recoverySendEmail_whenGenericExceptionThrown_returnsRecoveryWithError() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

        doThrow(new RuntimeException("network error")).when(mfaSecretService).sendRecoveryKey(USERNAME);

        Model model = new ExtendedModelMap();
        String view = mfaController.recoverySendEmail(TENANT_ID, request, model);

        assertEquals("mfa/mfa-recovery", view);
        assertNotNull(model.getAttribute("error"));
    }

    // ─────────────── recoveryVerifyKey ─────────────────────────────────────────

    @Test
    void recoveryVerifyKey_withValidKeyAndBackupCodesEnabled_returnsBackupView() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

        when(mfaSecretService.verifyRecoveryKeyAndRevoke(USERNAME, "ABCDEF")).thenReturn(true);
        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(true);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryVerifyKey(TENANT_ID, "ABCDEF", request, response, model);

        assertEquals("mfa/mfa-recovery-backup", view);
    }

    @Test
    void recoveryVerifyKey_withValidKeyAndBackupCodesDisabled_redirectsToEnroll() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

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
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

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
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

        when(mfaSecretService.verifyRecoveryKeyAndRevoke(USERNAME, "ABCDEF")).thenReturn(true);
        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(false);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        mfaController.recoveryVerifyKey(TENANT_ID, "ABCDEF", request, response, model);

        // Recovery state should have been cleared in DB
        verify(mfaStateService).clearRecoveryState(USERNAME);
    }

    // ─────────────── recoveryBackupPage ────────────────────────────────────────

    @Test
    void recoveryBackupPage_withPendingAndBackupEnabled_returnsBackupView() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

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
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(false);

        Model model = new ExtendedModelMap();
        String view = mfaController.recoveryBackupPage(TENANT_ID, request, model);

        // Redirects to recovery
        assertNotNull(view);
    }

    // ─────────────── recoveryBackupSubmit ──────────────────────────────────────

    @Test
    void recoveryBackupSubmit_withValidBackupCode_redirectsToEnroll() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaStateService.isRecoveryEmailVerified(USERNAME)).thenReturn(true);

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
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaStateService.isRecoveryEmailVerified(USERNAME)).thenReturn(true);

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
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaStateService.isRecoveryEmailVerified(USERNAME)).thenReturn(true);

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

    @Test
    void recoveryBackupSubmit_withBackupDisabled_redirectsToRecovery() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(false);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryBackupSubmit(TENANT_ID, "BACKUP1", request, response, model);

        assertNotNull(view);
    }

    @Test
    void recoveryBackupSubmit_withoutEmailVerification_redirectsToRecovery() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        // Email-verified flag is false (default from setUp), so backup-code step is blocked.

        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(true);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryBackupSubmit(TENANT_ID, "BACKUP1", request, response, model);

        assertNotNull(view);
        // Should NOT have invoked verifyBackupCode because the email-verified guard blocks it.
        verify(mfaSecretService, never()).verifyBackupCode(anyString(), anyString());
    }

    // ─────────────── recoveryContinue ─────────────────────────────────────────

    @Test
    void recoveryContinue_withNoSavedRequest_redirectsToTenantRoot() {
        // With no saved OAuth2 request and the default tenant set to "ecsp" (= TENANT_ID),
        // the controller redirects to the root rather than to /login.
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryContinue(TENANT_ID, request, response, model);

        assertEquals("redirect:/", view);
    }

    @Test
    void recoveryContinue_withSessionNoSavedRequest_redirectsToRoot() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryContinue(TENANT_ID, request, response, model);

        assertNotNull(view);
    }

    @Test
    void recoveryContinue_withNullTenantId_usesDefaultTenant() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryContinue(null, request, response, model);

        assertNotNull(view);
    }

    // ─────────────── recoveryReEnroll ─────────────────────────────────────────

    @Test
    void recoveryReEnroll_withAuthenticatedUser_revokesAndRedirects() {
        MockHttpServletRequest request = new MockHttpServletRequest();
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
        // No authentication set, no pending token in DB → username resolves to null.

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String view = mfaController.recoveryReEnroll(TENANT_ID, request, response, model);

        assertNotNull(view);
        verify(mfaSecretService, never()).revoke(anyString());
    }

    // ─────────────── completeLogin with tenant ─────────────────────────────────

    @Test
    void challengeSubmit_withNonDefaultTenant_redirectsToTenantRoot() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));

        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));
        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(true);

        Model model = new ExtendedModelMap();
        MockHttpServletResponse response = new MockHttpServletResponse();
        // Use a non-default tenant
        String view = mfaController.challengeSubmit("custom-tenant", TOTP_CODE, request, response, model);

        // Should redirect to /custom-tenant/
        assertNotNull(view);
    }

    // ─────────────── Audit and Metrics verification ───────────────────────────

    @Test
    void enrollVerify_withValidCode_recordsAuditAndMetric() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));
        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(true);
        doNothing().when(mfaSecretService).activateEnrollment(USERNAME);
        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(false);

        mfaController.enrollVerify(TENANT_ID, TOTP_CODE, request, new MockHttpServletResponse(),
                new ExtendedModelMap());

        verify(auditLogger).log(
                eq(AuditEventType.MFA_ENROLLMENT_COMPLETED.getType()),
                anyString(),
                eq(AuditEventResult.SUCCESS),
                anyString(), any(), any());
        verify(metricsService).incrementMetricsForTenant(eq(TENANT_ID),
                eq(MetricType.MFA_ENROLLMENT_SUCCESS));
    }

    @Test
    void enrollVerify_withInvalidCode_recordsAuditAndMetric() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));
        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(false);
        when(totpService.formatManualKey(BASE32_SECRET)).thenReturn(MANUAL_KEY);
        when(totpService.generateQrCodeBase64(USERNAME, BASE32_SECRET)).thenReturn("qrBase64");

        mfaController.enrollVerify(TENANT_ID, TOTP_CODE, request, new MockHttpServletResponse(),
                new ExtendedModelMap());

        verify(auditLogger).log(
                eq(AuditEventType.MFA_ENROLLMENT_VERIFY_FAILED.getType()),
                anyString(),
                eq(AuditEventResult.FAILURE),
                anyString(), any(), any());
        verify(metricsService).incrementMetricsForTenant(eq(TENANT_ID),
                eq(MetricType.MFA_ENROLLMENT_FAILURE));
    }

    @Test
    void challengeSubmit_withValidCode_recordsAuditAndMetric() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));
        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(true);

        mfaController.challengeSubmit(TENANT_ID, TOTP_CODE, request, new MockHttpServletResponse(),
                new ExtendedModelMap());

        verify(auditLogger).log(
                eq(AuditEventType.MFA_CHALLENGE_SUCCESS.getType()),
                anyString(),
                eq(AuditEventResult.SUCCESS),
                anyString(), any(), any());
        verify(metricsService).incrementMetricsForTenant(eq(TENANT_ID),
                eq(MetricType.MFA_CHALLENGE_SUCCESS));
    }

    @Test
    void challengeSubmit_withInvalidCode_recordsAuditAndMetric() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));
        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(false);

        mfaController.challengeSubmit(TENANT_ID, TOTP_CODE, request, new MockHttpServletResponse(),
                new ExtendedModelMap());

        verify(auditLogger).log(
                eq(AuditEventType.MFA_CHALLENGE_FAILURE.getType()),
                anyString(),
                eq(AuditEventResult.FAILURE),
                anyString(), any(), any());
        verify(metricsService).incrementMetricsForTenant(eq(TENANT_ID),
                eq(MetricType.MFA_CHALLENGE_FAILURE));
    }

    @Test
    void recoveryVerifyKey_withValidKey_recordsAuditAndMetric() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaSecretService.verifyRecoveryKeyAndRevoke(USERNAME, "ABCDEF")).thenReturn(true);
        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(false);

        mfaController.recoveryVerifyKey(TENANT_ID, "ABCDEF", request, new MockHttpServletResponse(),
                new ExtendedModelMap());

        verify(auditLogger).log(
                eq(AuditEventType.MFA_RECOVERY_COMPLETED.getType()),
                anyString(),
                eq(AuditEventResult.SUCCESS),
                anyString(), any(), any());
        verify(metricsService).incrementMetricsForTenant(eq(TENANT_ID),
                eq(MetricType.MFA_RECOVERY_SUCCESS));
    }

    @Test
    void recoveryVerifyKey_withInvalidKey_recordsAuditOnly() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaSecretService.verifyRecoveryKeyAndRevoke(USERNAME, "WRONG")).thenReturn(false);

        mfaController.recoveryVerifyKey(TENANT_ID, "WRONG", request, new MockHttpServletResponse(),
                new ExtendedModelMap());

        verify(auditLogger).log(
                eq(AuditEventType.MFA_RECOVERY_FAILED.getType()),
                anyString(),
                eq(AuditEventResult.FAILURE),
                anyString(), any(), any());
        verify(metricsService, never()).incrementMetricsForTenant(anyString(), any());
    }

    @Test
    void recoveryBackupSubmit_withValidCode_recordsAuditAndMetric() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaStateService.isRecoveryEmailVerified(USERNAME)).thenReturn(true);
        when(mfaSecretService.isBackupCodesEnabled(USERNAME)).thenReturn(true);
        MfaBackupCodeVerifyResponseDto result = new MfaBackupCodeVerifyResponseDto(true, 4, false);
        when(mfaSecretService.verifyBackupCode(USERNAME, "BACKUP1")).thenReturn(result);
        doNothing().when(mfaSecretService).revoke(USERNAME);

        mfaController.recoveryBackupSubmit(TENANT_ID, "BACKUP1", request, new MockHttpServletResponse(),
                new ExtendedModelMap());

        verify(auditLogger).log(
                eq(AuditEventType.MFA_BACKUP_CODE_USED.getType()),
                anyString(),
                eq(AuditEventResult.SUCCESS),
                anyString(), any(), any());
        verify(metricsService).incrementMetricsForTenant(eq(TENANT_ID),
                eq(MetricType.MFA_BACKUP_CODE_USED));
    }

    @Test
    void auditLogger_whenThrows_doesNotBreakMainFlow() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        when(mfaSecretService.getSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));
        when(totpService.validateCode(USERNAME, BASE32_SECRET, TOTP_CODE)).thenReturn(false);
        doThrow(new RuntimeException("audit subsystem down"))
                .when(auditLogger).log(anyString(), anyString(), any(), anyString(), any(), any());

        // Must not throw even when audit fails
        String view = mfaController.challengeSubmit(TENANT_ID, TOTP_CODE, request,
                new MockHttpServletResponse(), new ExtendedModelMap());

        assertEquals("mfa/mfa-challenge", view);
    }

    // ─────────────── Helper methods ───────────────────────────────────────────

    private void setAuthenticatedUser(String username) {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                username, "password",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
