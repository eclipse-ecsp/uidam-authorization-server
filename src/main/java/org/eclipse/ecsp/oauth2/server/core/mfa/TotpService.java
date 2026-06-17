package org.eclipse.ecsp.oauth2.server.core.mfa;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Production TOTP service implementing RFC 6238 TOTP with a ±1 time-step window.
 *
 * <p>Replaces {@code MockTotpService}. Same algorithm — debug secret logging removed.
 * QR code generation via ZXing stays unchanged.
 */
@Service
public class TotpService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TotpService.class);

    private static final int QR_WIDTH  = 300;
    private static final int QR_HEIGHT = 300;
    private static final int TOTP_DIGITS         = 6;
    private static final int TOTP_PERIOD_SECONDS = 30;

    private final String defaultIssuer;
    private final TenantConfigurationService tenantConfigurationService;

    // ...existing code (other constants)...
    private static final int  MILLIS_PER_SECOND  = 1000;
    private static final int  HMAC_BYTE_LENGTH   = 8;
    private static final int  LOW_NIBBLE_MASK    = 0x0F;
    private static final int  SIGN_BIT_MASK      = 0x7F;
    private static final int  BYTE_MASK          = 0xFF;
    private static final int  SHIFT_24           = 24;
    private static final int  SHIFT_16           = 16;
    private static final int  SHIFT_8            = 8;
    private static final int  BYTE_INDEX_2       = 2;
    private static final int  BYTE_INDEX_3       = 3;
    private static final int  BITS_PER_BASE32    = 5;
    private static final int  BITS_PER_BYTE      = 8;
    private static final int  TOTP_MODULUS       = 10;
    private static final int  GROUP_SIZE         = 4;

    /**
     * Constructs a TotpService with the configured application name.
     *
     * @param mfaProperties              MFA configuration properties
     * @param tenantConfigurationService service for tenant-specific configuration
     */
    public TotpService(MfaProperties mfaProperties, TenantConfigurationService tenantConfigurationService) {
        this.defaultIssuer = mfaProperties.getAppName();
        this.tenantConfigurationService = tenantConfigurationService;
    }

    /**
     * Build a Base64-encoded PNG QR code image from the given OTP-auth URI.
     *
     * <p>The auth server no longer generates the secret — it comes from user-management.
     * This method accepts the full {@code otpauth://} URI returned by user-management.
     *
     * @param otpAuthUri the full {@code otpauth://totp/...} URI
     * @return Base64-encoded PNG image string, or empty string on failure
     */
    public String generateQrCodeBase64FromUri(String otpAuthUri) {
        try {
            BitMatrix bitMatrix = new MultiFormatWriter().encode(
                    otpAuthUri, BarcodeFormat.QR_CODE, QR_WIDTH, QR_HEIGHT);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", baos);
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (Exception e) {
            LOGGER.error("[MFA] QR code generation failed for URI", e);
            return "";
        }
    }

    /**
     * Build a Base64-encoded PNG QR code from a username and secret.
     *
     * @param username the user's username
     * @param secret   the Base32 TOTP secret
     * @return Base64-encoded PNG image string
     */
    public String generateQrCodeBase64(String username, String secret) {
        String otpAuthUri = buildOtpAuthUri(username, secret);
        return generateQrCodeBase64FromUri(otpAuthUri);
    }

    /**
     * Validate a TOTP code for a given secret, allowing ±1 time-step window.
     *
     * @param username      the user's username (for logging only)
     * @param secret        the Base32 TOTP secret
     * @param submittedCode the 6-digit code submitted by the user
     * @return {@code true} if the code matches any of the three time windows
     */
    public boolean validateCode(String username, String secret, String submittedCode) {
        if (submittedCode == null || secret == null) {
            return false;
        }
        long now = System.currentTimeMillis();
        long currentStep = now / MILLIS_PER_SECOND / TOTP_PERIOD_SECONDS;

        boolean match = submittedCode.equals(computeTotp(secret, currentStep - 1))
                || submittedCode.equals(computeTotp(secret, currentStep))
                || submittedCode.equals(computeTotp(secret, currentStep + 1));

        LOGGER.info("[MFA] TOTP validation for user='{}': {}", username, match ? "SUCCESS" : "FAILURE");
        return match;
    }

    /**
     * Format a Base32 key as human-readable groups of 4: {@code JBSW Y3DP EHPK 3PXP}.
     *
     * @param secret the raw Base32 secret
     * @return the formatted manual-entry key
     */
    public String formatManualKey(String secret) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < secret.length(); i++) {
            if (i > 0 && i % GROUP_SIZE == 0) {
                sb.append(' ');
            }
            sb.append(secret.charAt(i));
        }
        return sb.toString();
    }

    /**
     * Build the otpauth:// URI for QR code generation.
     *
     * <p>The account label is formatted as {@code issuer-tenantId:username} when a non-default
     * tenant is active, matching the pattern used by
     * {@code MfaManagementService#buildOtpAuthUri} in the user-management service.
     * Spaces are encoded as {@code %20} (not {@code +}) as required by authenticator apps.
     */
    public String buildOtpAuthUri(String username, String secret) {
        try {
            String resolvedIssuer = resolveIssuer();
            // URLEncoder uses application/x-www-form-urlencoded rules (spaces → '+').
            // Authenticator apps expect RFC 3986 percent-encoding (spaces → '%20').
            String account   = URLEncoder.encode(resolvedIssuer + ":" + username, StandardCharsets.UTF_8)
                    .replace("+", "%20");
            String issuerEnc = URLEncoder.encode(resolvedIssuer, StandardCharsets.UTF_8)
                    .replace("+", "%20");
            return "otpauth://totp/" + account
                    + "?secret=" + secret
                    + "&issuer=" + issuerEnc
                    + "&digits=" + TOTP_DIGITS
                    + "&period=" + TOTP_PERIOD_SECONDS;
        } catch (Exception ex) {
            LOGGER.error("[MFA] URI encoding failed", ex);
        }
        return "otpauth://totp/" + defaultIssuer + ":" + username + "?secret=" + secret;
    }

    /**
     * Resolve the MFA issuer/app name from tenant properties, postfixing the tenant ID
     * when a non-default tenant is active — e.g. {@code UIDAM-acme}.
     *
     * <p>Mirrors {@code MfaManagementService#resolveIssuer()} in the user-management service
     * so that the issuer label is consistent across both services.
     *
     * @return the resolved issuer string for the current tenant context
     */
    private String resolveIssuer() {
        String appName = defaultIssuer;
        String tenantId = null;
        try {
            TenantProperties tenantProps = tenantConfigurationService.getTenantProperties();
            if (tenantProps != null) {
                if (tenantProps.getMfaAppName() != null && !tenantProps.getMfaAppName().isBlank()) {
                    appName = tenantProps.getMfaAppName();
                }
                if (tenantProps.getTenantId() != null && !tenantProps.getTenantId().isBlank()) {
                    tenantId = tenantProps.getTenantId();
                }
            }
        } catch (Exception ex) {
            LOGGER.debug("[MFA] Could not resolve tenant MFA app name, using default: {}", ex.getMessage());
        }
        if (tenantId != null && !tenantId.isBlank() && !"default".equalsIgnoreCase(tenantId)) {
            return appName + "-" + tenantId;
        }
        return appName;
    }

    /**
     * Compute RFC 6238 TOTP for a given Base32 secret and time step.
     */
    public String computeTotp(String base32Secret, long timeStep) {
        try {
            byte[] keyBytes  = decodeBase32(base32Secret);
            byte[] timeBytes = ByteBuffer.allocate(HMAC_BYTE_LENGTH).putLong(timeStep).array();

            Mac mac = Mac.getInstance("HmacSHA1"); // NOSONAR java:S4790 - TOTP (RFC 6238/4226) mandates HMAC-SHA1
            mac.init(new SecretKeySpec(keyBytes, "HmacSHA1"));
            byte[] hash = mac.doFinal(timeBytes);

            int offset = hash[hash.length - 1] & LOW_NIBBLE_MASK;
            int binary = ((hash[offset]                  & SIGN_BIT_MASK) << SHIFT_24)
                       | ((hash[offset + 1]              & BYTE_MASK)     << SHIFT_16)
                       | ((hash[offset + BYTE_INDEX_2]   & BYTE_MASK)     << SHIFT_8)
                       |  (hash[offset + BYTE_INDEX_3]   & BYTE_MASK);

            int otp = binary % (int) Math.pow(TOTP_MODULUS, TOTP_DIGITS);
            return String.format("%0" + TOTP_DIGITS + "d", otp);
        } catch (Exception e) {
            LOGGER.error("[MFA] TOTP computation error", e);
            return "";
        }
    }

    /**
     * Minimal Base32 decoder (RFC 4648, uppercase, no padding required).
     */
    private byte[] decodeBase32(String base32) {
        String upper    = base32.toUpperCase().replace("=", "");
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        int buffer   = 0;
        int bitsLeft = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (char c : upper.toCharArray()) {
            int val = alphabet.indexOf(c);
            if (val < 0) {
                continue;
            }
            buffer    = (buffer << BITS_PER_BASE32) | val;
            bitsLeft += BITS_PER_BASE32;
            if (bitsLeft >= BITS_PER_BYTE) {
                bitsLeft -= BITS_PER_BYTE;
                out.write((buffer >> bitsLeft) & BYTE_MASK);
            }
        }
        return out.toByteArray();
    }
}
