package org.eclipse.ecsp.oauth2.server.core.response.dto;

import java.util.List;

/**
 * Response DTO for MFA backup-code generation, mapping user-management's
 * {@code MfaBackupCodesResponse}.
 *
 * @param codes the freshly generated plain-text backup codes (one-time display)
 * @param count the number of codes generated
 */
public record MfaBackupCodesResponseDto(
        List<String> codes,
        int count
) {
}
