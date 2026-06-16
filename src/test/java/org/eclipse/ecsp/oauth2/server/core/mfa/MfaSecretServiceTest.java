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

import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaStatusResponseDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for MfaSecretService delegating to UserManagementClient.
 */
@ExtendWith(MockitoExtension.class)
class MfaSecretServiceTest {

    private static final String USERNAME = "testuser";
    private static final String BASE32_SECRET = "JBSWY3DPEHPK3PXP";
    private static final String BACKUP_CODE = "ABCDEF";
    private static final String RECOVERY_KEY = "123456";

    @Mock
    private UserManagementClient userManagementClient;

    private MfaSecretService mfaSecretService;

    @BeforeEach
    void setUp() {
        mfaSecretService = new MfaSecretService(userManagementClient);
    }

    // ─────────────── isEnrolled ───────────────────────────────────────────────

    @Test
    void isEnrolled_whenStatusIsActive_returnsTrue() {
        MfaStatusResponseDto status = new MfaStatusResponseDto(true, "ACTIVE", false);
        when(userManagementClient.getMfaStatus(USERNAME)).thenReturn(Optional.of(status));

        assertTrue(mfaSecretService.isEnrolled(USERNAME));
    }

    @Test
    void isEnrolled_whenStatusIsPending_returnsFalse() {
        MfaStatusResponseDto status = new MfaStatusResponseDto(false, "PENDING", false);
        when(userManagementClient.getMfaStatus(USERNAME)).thenReturn(Optional.of(status));

        assertFalse(mfaSecretService.isEnrolled(USERNAME));
    }

    @Test
    void isEnrolled_whenStatusIsNone_returnsFalse() {
        MfaStatusResponseDto status = new MfaStatusResponseDto(false, "NONE", false);
        when(userManagementClient.getMfaStatus(USERNAME)).thenReturn(Optional.of(status));

        assertFalse(mfaSecretService.isEnrolled(USERNAME));
    }

    @Test
    void isEnrolled_whenClientReturnsEmpty_returnsFalse() {
        when(userManagementClient.getMfaStatus(USERNAME)).thenReturn(Optional.empty());

        assertFalse(mfaSecretService.isEnrolled(USERNAME));
    }

    // ─────────────── hasPendingEnrollment ────────────────────────────────────

    @Test
    void hasPendingEnrollment_whenStatusIsPending_returnsTrue() {
        MfaStatusResponseDto status = new MfaStatusResponseDto(false, "PENDING", false);
        when(userManagementClient.getMfaStatus(USERNAME)).thenReturn(Optional.of(status));

        assertTrue(mfaSecretService.hasPendingEnrollment(USERNAME));
    }

    @Test
    void hasPendingEnrollment_whenStatusIsActive_returnsFalse() {
        MfaStatusResponseDto status = new MfaStatusResponseDto(true, "ACTIVE", false);
        when(userManagementClient.getMfaStatus(USERNAME)).thenReturn(Optional.of(status));

        assertFalse(mfaSecretService.hasPendingEnrollment(USERNAME));
    }

    @Test
    void hasPendingEnrollment_whenClientReturnsEmpty_returnsFalse() {
        when(userManagementClient.getMfaStatus(USERNAME)).thenReturn(Optional.empty());

        assertFalse(mfaSecretService.hasPendingEnrollment(USERNAME));
    }

    // ─────────────── isBackupCodesEnabled ────────────────────────────────────

    @Test
    void isBackupCodesEnabled_whenEnabledInStatus_returnsTrue() {
        MfaStatusResponseDto status = new MfaStatusResponseDto(true, "ACTIVE", true);
        when(userManagementClient.getMfaStatus(USERNAME)).thenReturn(Optional.of(status));

        assertTrue(mfaSecretService.isBackupCodesEnabled(USERNAME));
    }

    @Test
    void isBackupCodesEnabled_whenDisabledInStatus_returnsFalse() {
        MfaStatusResponseDto status = new MfaStatusResponseDto(true, "ACTIVE", false);
        when(userManagementClient.getMfaStatus(USERNAME)).thenReturn(Optional.of(status));

        assertFalse(mfaSecretService.isBackupCodesEnabled(USERNAME));
    }

    @Test
    void isBackupCodesEnabled_whenClientReturnsEmpty_returnsTrue() {
        when(userManagementClient.getMfaStatus(USERNAME)).thenReturn(Optional.empty());

        // Default should be true when status not available
        assertTrue(mfaSecretService.isBackupCodesEnabled(USERNAME));
    }

    // ─────────────── initiateEnrollment ──────────────────────────────────────

    @Test
    void initiateEnrollment_delegatesToClient() {
        MfaEnrollInitiateResponseDto dto = new MfaEnrollInitiateResponseDto(
                BASE32_SECRET, "otpauth://...", "JBSW Y3DP");
        when(userManagementClient.initiateMfaEnrollment(USERNAME)).thenReturn(dto);

        MfaEnrollInitiateResponseDto result = mfaSecretService.initiateEnrollment(USERNAME);

        assertNotNull(result);
        assertEquals(BASE32_SECRET, result.secret());
        verify(userManagementClient).initiateMfaEnrollment(USERNAME);
    }

    // ─────────────── activateEnrollment ──────────────────────────────────────

    @Test
    void activateEnrollment_delegatesToClient() {
        doNothing().when(userManagementClient).activateMfaEnrollment(USERNAME);

        mfaSecretService.activateEnrollment(USERNAME);

        verify(userManagementClient).activateMfaEnrollment(USERNAME);
    }

    // ─────────────── getSecret ────────────────────────────────────────────────

    @Test
    void getSecret_whenSecretExists_returnsSecret() {
        when(userManagementClient.getMfaSecret(USERNAME)).thenReturn(Optional.of(BASE32_SECRET));

        Optional<String> result = mfaSecretService.getSecret(USERNAME);

        assertTrue(result.isPresent());
        assertEquals(BASE32_SECRET, result.get());
    }

    @Test
    void getSecret_whenNoSecret_returnsEmpty() {
        when(userManagementClient.getMfaSecret(USERNAME)).thenReturn(Optional.empty());

        Optional<String> result = mfaSecretService.getSecret(USERNAME);

        assertFalse(result.isPresent());
    }

    // ─────────────── revoke ───────────────────────────────────────────────────

    @Test
    void revoke_delegatesToClient() {
        doNothing().when(userManagementClient).revokeMfaEnrollment(USERNAME);

        mfaSecretService.revoke(USERNAME);

        verify(userManagementClient).revokeMfaEnrollment(USERNAME);
    }

    // ─────────────── sendRecoveryKey ──────────────────────────────────────────

    @Test
    void sendRecoveryKey_delegatesToClient() {
        doNothing().when(userManagementClient).sendMfaRecoveryKey(USERNAME);

        mfaSecretService.sendRecoveryKey(USERNAME);

        verify(userManagementClient).sendMfaRecoveryKey(USERNAME);
    }

    // ─────────────── verifyRecoveryKeyAndRevoke ────────────────────────────────

    @Test
    void verifyRecoveryKeyAndRevoke_whenValid_returnsTrue() {
        when(userManagementClient.verifyMfaRecoveryKey(USERNAME, RECOVERY_KEY)).thenReturn(true);

        boolean result = mfaSecretService.verifyRecoveryKeyAndRevoke(USERNAME, RECOVERY_KEY);

        assertTrue(result);
    }

    @Test
    void verifyRecoveryKeyAndRevoke_whenInvalid_returnsFalse() {
        when(userManagementClient.verifyMfaRecoveryKey(USERNAME, RECOVERY_KEY)).thenReturn(false);

        boolean result = mfaSecretService.verifyRecoveryKeyAndRevoke(USERNAME, RECOVERY_KEY);

        assertFalse(result);
    }

    // ─────────────── generateBackupCodes ─────────────────────────────────────

    @Test
    void generateBackupCodes_delegatesToClient() {
        MfaBackupCodesResponseDto dto = new MfaBackupCodesResponseDto(
                List.of("CODE1", "CODE2"), 2);
        when(userManagementClient.generateMfaBackupCodes(USERNAME)).thenReturn(dto);

        MfaBackupCodesResponseDto result = mfaSecretService.generateBackupCodes(USERNAME);

        assertNotNull(result);
        assertEquals(2, result.count());
        verify(userManagementClient).generateMfaBackupCodes(USERNAME);
    }

    // ─────────────── verifyBackupCode ─────────────────────────────────────────

    @Test
    void verifyBackupCode_whenValid_returnsSuccessDto() {
        MfaBackupCodeVerifyResponseDto dto = new MfaBackupCodeVerifyResponseDto(true, 4, false);
        when(userManagementClient.verifyMfaBackupCode(USERNAME, BACKUP_CODE)).thenReturn(dto);

        MfaBackupCodeVerifyResponseDto result = mfaSecretService.verifyBackupCode(USERNAME, BACKUP_CODE);

        assertNotNull(result);
        assertTrue(result.valid());
        assertEquals(4, result.remainingBackupCodes());
    }

    @Test
    void verifyBackupCode_whenInvalid_returnsFailureDto() {
        MfaBackupCodeVerifyResponseDto dto = new MfaBackupCodeVerifyResponseDto(false, 3, false);
        when(userManagementClient.verifyMfaBackupCode(USERNAME, "WRONG")).thenReturn(dto);

        MfaBackupCodeVerifyResponseDto result = mfaSecretService.verifyBackupCode(USERNAME, "WRONG");

        assertNotNull(result);
        assertFalse(result.valid());
    }
}
