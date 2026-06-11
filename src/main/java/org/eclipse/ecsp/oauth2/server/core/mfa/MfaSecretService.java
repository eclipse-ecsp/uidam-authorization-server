package org.eclipse.ecsp.oauth2.server.core.mfa;

import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaStatusResponseDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Production MFA secret service that delegates all enrollment state management
 * to the {@code uidam-user-management} service via REST calls through {@link UserManagementClient}.
 *
 * <p>Replaces {@code MockMfaStore}.  The authorization server holds no MFA state in memory.
 */
@Service
public class MfaSecretService {

    private static final Logger LOGGER = LoggerFactory.getLogger(MfaSecretService.class);

    private final UserManagementClient userManagementClient;

    public MfaSecretService(UserManagementClient userManagementClient) {
        this.userManagementClient = userManagementClient;
    }

    /**
     * Return {@code true} if the user has an ACTIVE MFA enrollment in user-management.
     *
     * @param username the user's username
     * @return {@code true} if enrolled and ACTIVE
     */
    public boolean isEnrolled(String username) {
        return userManagementClient.getMfaStatus(username)
                .map(r -> "ACTIVE".equals(r.status()))
                .orElse(false);
    }

    /**
     * Return {@code true} if the user has a PENDING enrollment (secret generated, not yet verified).
     *
     * @param username the user's username
     * @return {@code true} if status is PENDING
     */
    public boolean hasPendingEnrollment(String username) {
        return userManagementClient.getMfaStatus(username)
                .map(r -> "PENDING".equals(r.status()))
                .orElse(false);
    }

    /**
     * Whether MFA backup (recovery) codes are enabled for the current tenant.
     *
     * <p>This is the single authoritative flag, owned by user-management
     * (tenant property {@code mfa-backup-codes-enabled}) and surfaced through the MFA status
     * endpoint. When the status call cannot be resolved the method defaults to {@code true} to
     * mirror user-management's own fallback behaviour.
     *
     * @param username the user's username
     * @return {@code true} if backup-code pages and flows should be shown
     */
    public boolean isBackupCodesEnabled(String username) {
        return userManagementClient.getMfaStatus(username)
                .map(MfaStatusResponseDto::backupCodesEnabled)
                .orElse(true);
    }

    /**
     * Initiate a new MFA enrollment – generates a secret and stores it as PENDING in user-management.
     *
     * @param username the user's username
     * @return {@link MfaEnrollInitiateResponseDto} with secret, QR URI, and manual key
     */
    public MfaEnrollInitiateResponseDto initiateEnrollment(String username) {
        LOGGER.info("[MFA] Initiating enrollment for user='{}'", username);
        return userManagementClient.initiateMfaEnrollment(username);
    }

    /**
     * Activate the enrollment in user-management after a successful TOTP verification.
     *
     * @param username the user's username
     */
    public void activateEnrollment(String username) {
        LOGGER.info("[MFA] Activating enrollment for user='{}'", username);
        userManagementClient.activateMfaEnrollment(username);
    }

    /**
     * Retrieve the TOTP secret from user-management for challenge validation.
     *
     * @param username the user's username
     * @return Optional containing the Base32 secret, or empty if not enrolled
     */
    public Optional<String> getSecret(String username) {
        return userManagementClient.getMfaSecret(username);
    }

    /**
     * Revoke the MFA enrollment (triggers re-enrollment on next login).
     *
     * @param username the user's username
     */
    public void revoke(String username) {
        LOGGER.info("[MFA] Revoking enrollment for user='{}'", username);
        userManagementClient.revokeMfaEnrollment(username);
    }

    /**
     * Send a one-time 6-character recovery key to the user's registered email.
     *
     * @param username the user's username
     */
    public void sendRecoveryKey(String username) {
        LOGGER.info("[MFA] Sending recovery key for user='{}'", username);
        userManagementClient.sendMfaRecoveryKey(username);
    }

    /**
     * Verify the recovery key. On success, the existing enrollment is revoked in user-management
     * and the user can re-enroll.
     *
     * @param username    the user's username
     * @param recoveryKey the 6-character key
     * @return {@code true} if the key was valid and enrollment is revoked
     */
    public boolean verifyRecoveryKeyAndRevoke(String username, String recoveryKey) {
        LOGGER.info("[MFA] Verifying recovery key for user='{}'", username);
        return userManagementClient.verifyMfaRecoveryKey(username, recoveryKey);
    }

    /**
     * Generate (or regenerate) a set of single-use backup codes for the user.
     *
     * @param username the user's username
     * @return {@link MfaBackupCodesResponseDto} containing the freshly generated plain-text codes
     */
    public MfaBackupCodesResponseDto generateBackupCodes(String username) {
        LOGGER.info("[MFA] Generating backup codes for user='{}'", username);
        return userManagementClient.generateMfaBackupCodes(username);
    }

    /**
     * Verify a single backup code. On success the code is consumed (single-use) in user-management.
     *
     * @param username   the user's username
     * @param backupCode the plain-text backup code entered by the user
     * @return {@link MfaBackupCodeVerifyResponseDto} with validity and remaining-code count
     */
    public MfaBackupCodeVerifyResponseDto verifyBackupCode(String username, String backupCode) {
        LOGGER.info("[MFA] Verifying backup code for user='{}'", username);
        return userManagementClient.verifyMfaBackupCode(username, backupCode);
    }
}
