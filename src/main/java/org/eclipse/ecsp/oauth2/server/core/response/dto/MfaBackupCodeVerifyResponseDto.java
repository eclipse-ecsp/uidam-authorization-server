package org.eclipse.ecsp.oauth2.server.core.response.dto;

/**
 * Response DTO for MFA backup-code verification, mapping user-management's
 * {@code MfaBackupCodeVerifyResponse}.
 *
 * @param valid                 {@code true} if the supplied code matched an unused backup code
 * @param remainingBackupCodes  number of unused backup codes left after this verification
 * @param lowBackupCodesWarning {@code true} when remaining codes are at or below the low threshold
 */
public record MfaBackupCodeVerifyResponseDto(
        boolean valid,
        int remainingBackupCodes,
        boolean lowBackupCodesWarning
) {
}
