package org.eclipse.ecsp.oauth2.server.core.response.dto;

/**
 * Response DTO for MFA status query, mapping user-management's {@code MfaStatusResponse}.
 *
 * @param enrolled {@code true} if the user has an ACTIVE MFA enrollment
 * @param status   String status: {@code NONE | PENDING | ACTIVE | REVOKED}
 * @param backupCodesEnabled {@code true} when the tenant has MFA backup (recovery) codes enabled.
 *                 Single authoritative flag owned by user-management ({@code mfa-backup-codes-enabled}).
 */
public record MfaStatusResponseDto(
        boolean enrolled,
        String status,
        boolean backupCodesEnabled
) {
}
