package org.eclipse.ecsp.oauth2.server.core.response.dto;

/**
 * Response DTO for MFA enrollment initiation, mapping user-management's
 * {@code MfaEnrollInitiateResponse}.
 *
 * @param secret    Base32-encoded TOTP secret (shown to user once for manual entry)
 * @param qrUri     Full {@code otpauth://} URI for QR code generation
 * @param manualKey Human-readable, space-separated key groups of 4 characters
 */
public record MfaEnrollInitiateResponseDto(
        String secret,
        String qrUri,
        String manualKey
) {
}
