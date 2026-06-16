package org.eclipse.ecsp.oauth2.server.core.mfa;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Collections;

import static org.eclipse.ecsp.oauth2.server.core.mfa.MfaChallengeFilter.SESSION_MFA_PENDING;
import static org.eclipse.ecsp.oauth2.server.core.mfa.MfaChallengeFilter.SESSION_MFA_TENANT;

/**
 * Handles all /mfa/** and /{tenantId}/mfa/** endpoints for the MFA (TOTP) login, enrollment, and recovery flows.
 *
 * <p>Flows:
 * <ul>
 *   <li>{@code [/{tenantId}]/mfa/enroll/setup}  – show QR code and manual key</li>
 *   <li>{@code [/{tenantId}]/mfa/enroll/verify} – verify first code and activate enrollment</li>
 *   <li>{@code [/{tenantId}]/mfa/challenge}     – submit TOTP code to complete login</li>
 * </ul>
 */
@Controller
public class MfaController {

    private static final Logger LOGGER = LoggerFactory.getLogger(MfaController.class);

    private static final String REDIRECT_PREFIX      = "redirect:";
    private static final String REDIRECT_LOGIN       = REDIRECT_PREFIX + "/login";
    private static final String REDIRECT_ROOT        = REDIRECT_PREFIX + "/";
    private static final String PATH_ENROLL_SETUP    = "/mfa/enroll/setup";
    private static final String REDIRECT_ENROLL_SETUP = REDIRECT_PREFIX + PATH_ENROLL_SETUP;
    private static final String ATTR_USERNAME        = "username";
    private static final String ATTR_ERROR           = "error";
    private static final String ATTR_SECRET          = "secret";
    private static final String ATTR_MANUAL_KEY      = "manualKey";
    private static final String ATTR_QR_BASE64       = "qrBase64";
    private static final String ATTR_TENANT          = "tenantId";
    private static final String ATTR_APP_NAME        = "appName";
    private static final String SESSION_ENROLL_SECRET   = "MFA_ENROLL_SECRET";
    private static final String SESSION_ENROLL_USERNAME = "MFA_ENROLL_USERNAME";
    private static final String SESSION_BACKUP_USERNAME = "MFA_BACKUP_CODES_PENDING_USERNAME";
    private static final String SESSION_BACKUP_TENANT   = "MFA_BACKUP_CODES_PENDING_TENANT";
    /** Set after a successful email recovery-key verification; gates backup-code entry. */
    private static final String SESSION_RECOVERY_EMAIL_VERIFIED = "MFA_RECOVERY_EMAIL_VERIFIED";

    private static final String VIEW_ENROLL_SETUP      = "mfa/mfa-enroll-setup";
    private static final String VIEW_ENROLL_BACKUP_CODES = "mfa/mfa-enroll-backup-codes";
    private static final String VIEW_CHALLENGE          = "mfa/mfa-challenge";
    private static final String VIEW_RECOVERY           = "mfa/mfa-recovery";
    private static final String VIEW_RECOVERY_BACKUP    = "mfa/mfa-recovery-backup";
    private static final String VIEW_RECOVERY_VERIFY    = "mfa/mfa-recovery-verify";
    private static final String VIEW_ERROR              = "mfa/mfa-error";

    private static final String ATTR_BACKUP_CODES       = "backupCodes";
    private static final String ATTR_REMAINING_CODES    = "remainingBackupCodes";
    private static final String ATTR_RESEND_COOLDOWN    = "resendCooldownSeconds";
    private static final String ATTR_EMAIL_SENT         = "emailSent";
    private static final String ERR_RECOVERY_EMAIL_SEND =
            "Unable to send the recovery code to your email. Please try again later or contact your administrator.";
    private static final String SESSION_RECOVERY_SENT_AT = "MFA_RECOVERY_SENT_AT";
    private static final long MILLIS_PER_SECOND = 1000L;

    private final MfaSecretService mfaSecretService;
    private final TotpService totpService;
    private final MfaProperties mfaProperties;
    private final TenantConfigurationService tenantConfigurationService;

    /**
     * Constructs an MfaController.
     *
     * @param mfaSecretService    production MFA secret service (delegates to user-management).
     * @param totpService         TOTP utility service for code validation and QR generation.
     * @param mfaProperties       MFA configuration properties.
     * @param tenantConfigurationService service for tenant-specific configuration.
     */
    public MfaController(MfaSecretService mfaSecretService, TotpService totpService,
            MfaProperties mfaProperties,
            TenantConfigurationService tenantConfigurationService) {
        this.mfaSecretService     = mfaSecretService;
        this.totpService          = totpService;
        this.mfaProperties        = mfaProperties;
        this.tenantConfigurationService = tenantConfigurationService;
    }

    /**
     * Expose the configured application name to all Thymeleaf views handled by this controller.
     *
     * @return the MFA application display name
     */
    @org.springframework.web.bind.annotation.ModelAttribute(ATTR_APP_NAME)
    public String populateAppName() {
        return resolveMfaAppName();
    }

    /**
     * Resolve the MFA app/issuer name from tenant properties, falling back to MfaProperties default.
     *
     * @return the MFA application display name for the current tenant
     */
    private String resolveMfaAppName() {
        String appName = mfaProperties.getAppName();
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
        if (tenantId != null && !"default".equalsIgnoreCase(tenantId)) {
            return appName + " - " + tenantId;
        }
        return appName;
    }

    /**
     * Whether the MFA backup-code feature is enabled for the current tenant.
     *
     * <p>The authoritative per-tenant enable flag is owned by user-management
     * (tenant property {@code mfa-backup-codes-enabled}) and is surfaced through the MFA status
     * endpoint. A single property therefore controls both services.
     *
     * @param username the user's username
     * @return {@code true} if backup-code pages and flows should be shown
     */
    private boolean isBackupCodesEnabled(String username) {
        return mfaSecretService.isBackupCodesEnabled(username);
    }

    // ─────────────────────────── ENROLLMENT ────────────────────────────────

    /**
     * Show the MFA enrollment setup page with a QR code.
     * Handles both /{tenantId}/mfa/enroll/setup and /mfa/enroll/setup.
     *
     * @param tenantId optional tenant path variable.
     * @param request  the HTTP request.
     * @param model    the Thymeleaf model.
     * @return view name.
     */
    @GetMapping({"/{tenantId}/mfa/enroll/setup", "/mfa/enroll/setup"})
    public String enrollSetup(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            HttpServletRequest request, Model model) {

        final String resolvedTenant = resolveTenant(tenantId, request);
        String username = resolveUsername(request);
        if (username == null) {
            LOGGER.warn("[MFA] /mfa/enroll/setup – unauthenticated or anonymous access denied");
            model.addAttribute(ATTR_ERROR,
                    "Unauthorized: You must be logged in to access MFA enrollment.");
            return VIEW_ERROR;
        }

        // Initiate enrollment in user-management: generates secret, stores as PENDING
        MfaEnrollInitiateResponseDto enrollData = mfaSecretService.initiateEnrollment(username);
        String secret    = enrollData.secret();

        HttpSession session = request.getSession(true);
        session.setAttribute(SESSION_ENROLL_SECRET, secret);
        session.setAttribute(SESSION_ENROLL_USERNAME, username);
        session.setAttribute(SESSION_MFA_TENANT, resolvedTenant);

        final String manualKey = enrollData.manualKey() != null
                ? enrollData.manualKey() : totpService.formatManualKey(secret);
        final String qrBase64  = totpService.generateQrCodeBase64FromUri(enrollData.qrUri());

        LOGGER.info("[MFA] Enrollment setup tenant='{}' user='{}'", resolvedTenant, username);

        model.addAttribute(ATTR_TENANT,     resolvedTenant);
        model.addAttribute(ATTR_USERNAME,   username);
        model.addAttribute(ATTR_MANUAL_KEY, manualKey);
        model.addAttribute(ATTR_QR_BASE64,  qrBase64);
        return VIEW_ENROLL_SETUP;
    }

    /**
     * Verify the first TOTP code and activate MFA enrollment.
     * Handles both /{tenantId}/mfa/enroll/verify and /mfa/enroll/verify.
     *
     * @param tenantId optional tenant path variable.
     * @param totpCode the 6-digit code from the authenticator app.
     * @param request  the HTTP request.
     * @param model    the Thymeleaf model.
     * @return view name.
     */
    @PostMapping({"/{tenantId}/mfa/enroll/verify", "/mfa/enroll/verify"})
    public String enrollVerify(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            @RequestParam("totpCode") String totpCode,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        HttpSession session = request.getSession(false);
        if (session == null) {
            return REDIRECT_LOGIN;
        }

        String resolvedTenant = resolveTenant(tenantId, request);
        String secret   = (String) session.getAttribute(SESSION_ENROLL_SECRET);
        String username = (String) session.getAttribute(SESSION_ENROLL_USERNAME);

        if (secret == null || username == null) {
            model.addAttribute(ATTR_ERROR, "Enrollment session expired. Please try again.");
            return VIEW_ERROR;
        }

        LOGGER.info("[MFA] Enrollment verify tenant='{}' user='{}'",
                resolvedTenant, username);
        if (totpService.validateCode(username, secret, totpCode)) {
            mfaSecretService.activateEnrollment(username);
            session.removeAttribute(SESSION_ENROLL_SECRET);
            session.removeAttribute(SESSION_ENROLL_USERNAME);
            LOGGER.info("[MFA] Enrollment VERIFIED for user='{}'", username);

            // Stash the data needed to complete login after the user acknowledges this page.
            session.setAttribute(SESSION_BACKUP_USERNAME, username);
            session.setAttribute(SESSION_BACKUP_TENANT, resolvedTenant);
            model.addAttribute(ATTR_TENANT, resolvedTenant);

            // When backup codes are enabled, generate a fresh set and show them once.
            if (isBackupCodesEnabled(username)) {
                try {
                    MfaBackupCodesResponseDto codes = mfaSecretService.generateBackupCodes(username);
                    model.addAttribute(ATTR_BACKUP_CODES, codes != null ? codes.codes() : Collections.emptyList());
                    LOGGER.info("[MFA] Generated backup codes for user='{}' during enrollment", username);
                } catch (Exception ex) {
                    LOGGER.error("[MFA] Failed to generate backup codes for user='{}': {}", username, ex.getMessage());
                    model.addAttribute(ATTR_BACKUP_CODES, Collections.emptyList());
                }
            } else {
                model.addAttribute(ATTR_BACKUP_CODES, Collections.emptyList());
            }
            return VIEW_ENROLL_BACKUP_CODES;
        }

        LOGGER.warn("[MFA] Enrollment verification FAILED for user='{}'", username);
        model.addAttribute(ATTR_ERROR,      "Invalid code. Please check your authenticator app and try again.");
        model.addAttribute(ATTR_TENANT,     resolvedTenant);
        model.addAttribute(ATTR_USERNAME,   username);
        model.addAttribute(ATTR_SECRET,     secret);
        model.addAttribute(ATTR_MANUAL_KEY, totpService.formatManualKey(secret));
        model.addAttribute(ATTR_QR_BASE64,  totpService.generateQrCodeBase64(username, secret));
        return VIEW_ENROLL_SETUP;
    }

    // ─────────────────────── BACKUP CODES CONFIRM ──────────────────────────

    /**
     * User confirms they have saved their backup codes; complete login.
     * Handles both /{tenantId}/mfa/enroll/backup-codes/confirm and the non-tenant form.
     */
    @PostMapping({"/{tenantId}/mfa/enroll/backup-codes/confirm", "/mfa/enroll/backup-codes/confirm"})
    public String backupCodesConfirm(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        HttpSession session = request.getSession(false);
        if (session == null) {
            return REDIRECT_LOGIN;
        }
        // Read and immediately consume the session attributes in one block
        final String username    = (String)  session.getAttribute(SESSION_BACKUP_USERNAME);
        final String storedTenant = (String) session.getAttribute(SESSION_BACKUP_TENANT);
        session.removeAttribute(SESSION_BACKUP_USERNAME);
        session.removeAttribute(SESSION_BACKUP_TENANT);

        if (username == null) {
            model.addAttribute(ATTR_ERROR, "Session expired. Please log in again.");
            return VIEW_ERROR;
        }

        String resolvedTenant = resolveTenant(storedTenant != null ? storedTenant : tenantId, request);
        return completeLogin(username, resolvedTenant, session, request, response);
    }

    // ─────────────────────────── CHALLENGE ─────────────────────────────────

    /**
     * Display the TOTP code entry page.
     * Handles both /{tenantId}/mfa/challenge and /mfa/challenge.
     *
     * @param tenantId optional tenant path variable.
     * @param request  the HTTP request.
     * @param model    the Thymeleaf model.
     * @return view name.
     */
    @GetMapping({"/{tenantId}/mfa/challenge", "/mfa/challenge"})
    public String challengePage(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            HttpServletRequest request, Model model) {

        MfaPendingAuthenticationToken pending = getPending(request);
        if (pending == null) {
            return REDIRECT_LOGIN;
        }
        String resolvedTenant = resolveTenant(tenantId, request);
        model.addAttribute(ATTR_TENANT,           resolvedTenant);
        model.addAttribute(ATTR_USERNAME,          pending.getPrincipal());
        return VIEW_CHALLENGE;
    }

    /**
     * Validate the submitted TOTP code and complete login on success.
     * Handles both /{tenantId}/mfa/challenge and /mfa/challenge.
     *
     * @param tenantId optional tenant path variable.
     * @param totpCode the 6-digit code from the authenticator app.
     * @param request  the HTTP request.
     * @param model    the Thymeleaf model.
     * @return view name or redirect.
     */
    @PostMapping({"/{tenantId}/mfa/challenge", "/mfa/challenge"})
    public String challengeSubmit(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            @RequestParam("totpCode") String totpCode,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        HttpSession session = request.getSession(false);
        MfaPendingAuthenticationToken pending = getPending(request);

        if (pending == null) {
            return REDIRECT_LOGIN;
        }

        String resolvedTenant = resolveTenant(tenantId, request);
        String username = (String) pending.getPrincipal();
        String secret   = mfaSecretService.getSecret(username).orElse(null);

        LOGGER.info("[MFA] Challenge attempt tenant='{}' user='{}'",
                resolvedTenant, username);
        if (secret != null && totpService.validateCode(username, secret, totpCode)) {
            session.removeAttribute(SESSION_MFA_PENDING);
            return completeLogin(username, resolvedTenant, session, request, response);
        }

        LOGGER.warn("[MFA] Challenge FAILED for user='{}'", username);
        model.addAttribute(ATTR_TENANT,   resolvedTenant);
        model.addAttribute(ATTR_USERNAME, username);
        model.addAttribute(ATTR_ERROR,    "Invalid code. Please try again.");
        return VIEW_CHALLENGE;
    }

    // ─────────────────────────── RE-ENROLL ─────────────────────────────────

    /**
     * Revoke the current user's MFA enrollment and redirect to setup.
     * This allows recovery when the authenticator app is lost/deleted.
     * Handles both /{tenantId}/mfa/re-enroll and /mfa/re-enroll.
     *
     * @param pathTenantId  tenant ID from the URL path variable (may be null).
     * @param paramTenantId tenant ID from a request parameter fallback (may be null).
     * @param request        the HTTP request.
     * @param response       the HTTP response.
     * @param model          the Thymeleaf model.
     * @return redirect to enrollment setup.
     */
    @GetMapping({"/{tenantId}/mfa/re-enroll", "/mfa/re-enroll"})
    public String reEnroll(
            @PathVariable(value = "tenantId", required = false) String pathTenantId,
            @RequestParam(value = "tenantId", required = false) String paramTenantId,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        // Prefer path variable, then request param, then session/default
        String effectiveTenantId = (pathTenantId != null && !pathTenantId.isEmpty())
                ? pathTenantId : paramTenantId;
        String resolvedTenant = resolveTenant(effectiveTenantId, request);
        String username = resolveUsername(request);

        if (username == null) {
            LOGGER.warn("[MFA] /mfa/re-enroll – unauthenticated or anonymous access denied");
            model.addAttribute(ATTR_ERROR,
                    "Unauthorized: You must be logged in to reset MFA enrollment.");
            return VIEW_ERROR;
        }

        LOGGER.info("[MFA] Re-enrollment requested for user='{}' tenant='{}'", username, resolvedTenant);
        mfaSecretService.revoke(username);

        return redirectToEnrollSetup(resolvedTenant);
    }

    // ─────────────────────────── RECOVERY ──────────────────────────────────

    /**
     * Display the recovery options page – offers email-based recovery.
     */
    @GetMapping({"/{tenantId}/mfa/recovery", "/mfa/recovery"})
    public String recoveryPage(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            HttpServletRequest request, Model model) {

        MfaPendingAuthenticationToken pending = getPending(request);
        if (pending == null) {
            return REDIRECT_LOGIN;
        }
        String resolvedTenant = resolveTenant(tenantId, request);
        String username = (String) pending.getPrincipal();
        model.addAttribute(ATTR_TENANT,          resolvedTenant);
        model.addAttribute(ATTR_USERNAME,         username);
        model.addAttribute(ATTR_REMAINING_CODES,  0);
        return VIEW_RECOVERY;
    }

    /**
     * Send the recovery email and redirect to the verification page.
     */
    @PostMapping({"/{tenantId}/mfa/recovery/send-email", "/mfa/recovery/send-email"})
    public String recoverySendEmail(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            HttpServletRequest request, Model model) {

        MfaPendingAuthenticationToken pending = getPending(request);
        if (pending == null) {
            return REDIRECT_LOGIN;
        }
        String resolvedTenant = resolveTenant(tenantId, request);
        String username = (String) pending.getPrincipal();
        HttpSession session = request.getSession(true);

        // Rate-limit: check cooldown
        Long lastSentAt = (Long) session.getAttribute(SESSION_RECOVERY_SENT_AT);
        int cooldown = mfaProperties.getRecovery().getResendCooldownSeconds();
        if (lastSentAt != null) {
            long elapsed = (System.currentTimeMillis() - lastSentAt) / MILLIS_PER_SECOND;
            if (elapsed < cooldown) {
                model.addAttribute(ATTR_TENANT, resolvedTenant);
                model.addAttribute(ATTR_USERNAME, username);
                model.addAttribute(ATTR_RESEND_COOLDOWN, cooldown);
                model.addAttribute(ATTR_ERROR,
                        "Please wait " + (cooldown - elapsed) + " seconds before requesting a new code.");
                return VIEW_RECOVERY_VERIFY;
            }
        }

        try {
            mfaSecretService.sendRecoveryKey(username);
            session.setAttribute(SESSION_RECOVERY_SENT_AT, System.currentTimeMillis());
        } catch (org.springframework.security.oauth2.core.OAuth2AuthenticationException oauthEx) {
            LOGGER.error("[MFA] Failed to send recovery email for user='{}': {}", username, oauthEx.getMessage());
            model.addAttribute(ATTR_TENANT, resolvedTenant);
            model.addAttribute(ATTR_USERNAME, username);
            model.addAttribute(ATTR_ERROR, ERR_RECOVERY_EMAIL_SEND);
            return VIEW_RECOVERY;
        } catch (Exception ex) {
            LOGGER.error("[MFA] Failed to send recovery email for user='{}': {}", username, ex.getMessage());
            model.addAttribute(ATTR_TENANT, resolvedTenant);
            model.addAttribute(ATTR_USERNAME, username);
            model.addAttribute(ATTR_ERROR, ERR_RECOVERY_EMAIL_SEND);
            return VIEW_RECOVERY;
        }

        model.addAttribute(ATTR_TENANT, resolvedTenant);
        model.addAttribute(ATTR_USERNAME, username);
        model.addAttribute(ATTR_RESEND_COOLDOWN, cooldown);
        model.addAttribute(ATTR_EMAIL_SENT, "A security code has been sent to your registered email address.");
        return VIEW_RECOVERY_VERIFY;
    }

    /**
     * Verify the 6-character recovery key submitted by the user.
     * On success: revoke enrollment and redirect to re-enrollment setup.
     */
    @PostMapping({"/{tenantId}/mfa/recovery/verify-key", "/mfa/recovery/verify-key"})
    public String recoveryVerifyKey(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            @RequestParam("recoveryKey") String recoveryKey,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        MfaPendingAuthenticationToken pending = getPending(request);
        if (pending == null) {
            return REDIRECT_LOGIN;
        }

        String resolvedTenant = resolveTenant(tenantId, request);
        String username = (String) pending.getPrincipal();

        LOGGER.info("[MFA] Recovery key verification attempt for user='{}' tenant='{}'",
                username, resolvedTenant);

        boolean valid = mfaSecretService.verifyRecoveryKeyAndRevoke(username, recoveryKey);
        if (valid) {
            LOGGER.info("[MFA] Recovery key verified – enrollment revoked for user='{}'", username);

            // Clear recovery cooldown
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(SESSION_RECOVERY_SENT_AT);
            }

            // Second factor for recovery: when backup codes are enabled, require the user to
            // also present a valid backup code before they are allowed to re-enroll.
            if (isBackupCodesEnabled(username)) {
                HttpSession verifiedSession = request.getSession(true);
                verifiedSession.setAttribute(SESSION_RECOVERY_EMAIL_VERIFIED, Boolean.TRUE);
                LOGGER.info("[MFA] Email recovery verified – prompting for backup code for user='{}'", username);
                model.addAttribute(ATTR_TENANT, resolvedTenant);
                model.addAttribute(ATTR_USERNAME, username);
                return VIEW_RECOVERY_BACKUP;
            }

            // Backup codes disabled – go straight to re-enrollment.
            return redirectToEnrollSetup(resolvedTenant);
        }

        model.addAttribute(ATTR_TENANT, resolvedTenant);
        model.addAttribute(ATTR_USERNAME, username);
        model.addAttribute(ATTR_RESEND_COOLDOWN, mfaProperties.getRecovery().getResendCooldownSeconds());
        model.addAttribute(ATTR_ERROR,
                "Invalid or expired security code. Please check your email and try again.");
        return VIEW_RECOVERY_VERIFY;
    }

    /**
     * Display the backup-code entry form.
     */
    @GetMapping({"/{tenantId}/mfa/recovery/backup-code", "/mfa/recovery/backup-code"})
    public String recoveryBackupPage(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            HttpServletRequest request, Model model) {

        MfaPendingAuthenticationToken pending = getPending(request);
        if (pending == null) {
            return REDIRECT_LOGIN;
        }
        if (!isBackupCodesEnabled((String) pending.getPrincipal())) {
            LOGGER.warn("[MFA] Backup-code recovery requested but feature is disabled");
            return redirectToRecovery(resolveTenant(tenantId, request));
        }
        model.addAttribute(ATTR_TENANT,   resolveTenant(tenantId, request));
        model.addAttribute(ATTR_USERNAME, pending.getPrincipal());
        return VIEW_RECOVERY_BACKUP;
    }

    /**
     * Submit a backup code for validation as the second step of account recovery.
     *
     * <p>This endpoint is only reachable after the user has already verified the email recovery
     * key (guarded by {@link #SESSION_RECOVERY_EMAIL_VERIFIED}). On a valid backup code the old
     * enrollment is revoked and the user is routed to fresh enrollment setup; on failure the form
     * is redisplayed with an error.
     */
    @PostMapping({"/{tenantId}/mfa/recovery/backup-code", "/mfa/recovery/backup-code"})
    public String recoveryBackupSubmit(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            @RequestParam("backupCode") String backupCode,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        MfaPendingAuthenticationToken pending = getPending(request);
        if (pending == null) {
            return REDIRECT_LOGIN;
        }

        String resolvedTenant = resolveTenant(tenantId, request);
        String username = (String) pending.getPrincipal();

        if (!isBackupCodesEnabled(username)) {
            LOGGER.warn("[MFA] Backup-code recovery submitted but feature is disabled for user='{}'", username);
            return redirectToRecovery(resolvedTenant);
        }

        // Ensure the email recovery key was verified first.
        HttpSession session = request.getSession(false);
        boolean emailVerified = session != null
                && Boolean.TRUE.equals(session.getAttribute(SESSION_RECOVERY_EMAIL_VERIFIED));
        if (!emailVerified) {
            LOGGER.warn("[MFA] Backup-code recovery without prior email verification for user='{}'", username);
            model.addAttribute(ATTR_TENANT, resolvedTenant);
            model.addAttribute(ATTR_USERNAME, username);
            return redirectToRecovery(resolvedTenant);
        }

        LOGGER.info("[MFA] Backup-code recovery attempt for user='{}' tenant='{}'",
                username, resolvedTenant);

        MfaBackupCodeVerifyResponseDto result = mfaSecretService.verifyBackupCode(username, backupCode);
        if (result != null && result.valid()) {
            LOGGER.info("[MFA] Backup-code verified for user='{}', remaining={}",
                    username, result.remainingBackupCodes());
            session.removeAttribute(SESSION_RECOVERY_EMAIL_VERIFIED);
            session.removeAttribute(SESSION_RECOVERY_SENT_AT);

            // Revoke the lost enrollment, then force re-enrollment.
            mfaSecretService.revoke(username);
            return redirectToEnrollSetup(resolvedTenant);
        }

        LOGGER.warn("[MFA] Backup-code recovery FAILED for user='{}'", username);
        model.addAttribute(ATTR_TENANT,   resolvedTenant);
        model.addAttribute(ATTR_USERNAME, username);
        model.addAttribute(ATTR_ERROR,
                "Invalid backup code. Please check the code you saved at enrollment and try again.");
        return VIEW_RECOVERY_BACKUP;
    }

    /**
     * After recovery success, user clicks "Continue without re-enrolling".
     * Resumes the original OAuth2 saved request.
     */
    @GetMapping({"/{tenantId}/mfa/recovery/continue", "/mfa/recovery/continue"})
    public String recoveryContinue(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        final String resolvedTenant = resolveTenant(tenantId, request);
        HttpSession session = request.getSession(false);
        if (session == null) {
            return REDIRECT_LOGIN;
        }
        // Resume the saved OAuth2 request now that the user has chosen to continue
        CookieRequestCache requestCache = new CookieRequestCache();
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            String redirectUrl = savedRequest.getRedirectUrl();
            LOGGER.info("[MFA] Recovery continue – resuming OAuth2 request: {}", redirectUrl);
            requestCache.removeRequest(request, response);
            return REDIRECT_PREFIX + redirectUrl;
        }
        LOGGER.warn("[MFA] Recovery continue – no saved OAuth2 request, redirecting to root");
        String defaultTenant = TenantUtils.getDefaultTenant();
        if (resolvedTenant != null && !resolvedTenant.isEmpty()
                && !resolvedTenant.equals(defaultTenant)) {
            return REDIRECT_ROOT + resolvedTenant + "/";
        }
        return REDIRECT_ROOT;
    }

    /**
     * After recovery success, user clicks "Re-enroll now" — revoke old enrollment and
     * route to fresh enrollment setup. The saved OAuth2 request remains in session so
     * it can be resumed after the new enrollment is confirmed.
     */
    @PostMapping({"/{tenantId}/mfa/recovery/re-enroll", "/mfa/recovery/re-enroll"})
    public String recoveryReEnroll(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        String resolvedTenant = resolveTenant(tenantId, request);
        String username = resolveUsername(request);

        if (username != null) {
            LOGGER.info("[MFA] Recovery re-enroll: revoking old enrollment for user='{}'", username);
            mfaSecretService.revoke(username);
        }

        return redirectToEnrollSetup(resolvedTenant);
    }

    // ─────────────────────────── HELPERS ───────────────────────────────────

    /**
     * Restore a full authenticated token into the security context so Spring
     * Security/OAuth2 can proceed with the original authorization request.
     *
     * @param username        the authenticated username.
     * @param resolvedTenant  the resolved tenant ID.
     * @param session         the current HTTP session.
     * @param request         the HTTP request (needed to retrieve the saved OAuth2 request).
     * @param response        the HTTP response (needed for RequestCache lookup and cookie).
     * @return redirect string to resume the OAuth flow.
     */
    private String completeLogin(String username, String resolvedTenant,
            HttpSession session, HttpServletRequest request, HttpServletResponse response) {
        MfaPendingAuthenticationToken pending =
                (MfaPendingAuthenticationToken) session.getAttribute(SESSION_MFA_PENDING);

        UsernamePasswordAuthenticationToken fullAuth =
                new UsernamePasswordAuthenticationToken(
                        username, null,
                        pending != null ? pending.getPendingAuthorities() : Collections.emptyList());

        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(fullAuth);
        SecurityContextHolder.setContext(ctx);
        session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, ctx);
        session.removeAttribute(SESSION_MFA_PENDING);
        session.removeAttribute(SESSION_MFA_TENANT);

        LOGGER.info("[MFA] Login completed tenant='{}' user='{}' – resuming OAuth flow",
                resolvedTenant, username);

        // matchingRequestParameterName not needed — CookieRequestCache stores the full
        // OAuth2 authorize URL in a cookie; no session key or ?continue param required.
        CookieRequestCache requestCache = new CookieRequestCache();
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            String redirectUrl = savedRequest.getRedirectUrl();
            LOGGER.info("[MFA] Resuming saved OAuth2 request: {}", redirectUrl);
            // Mark MFA as verified in session so MfaChallengeFilter does not re-intercept
            // the upcoming /oauth2/authorize redirect and loop back to challenge.
            session.setAttribute(MfaChallengeFilter.SESSION_MFA_VERIFIED, Boolean.TRUE);
            requestCache.removeRequest(request, response);
            return REDIRECT_PREFIX + redirectUrl;
        }

        LOGGER.warn("[MFA] No saved OAuth2 request found in session, redirecting to root");
        String defaultTenant = TenantUtils.getDefaultTenant();
        if (resolvedTenant != null && !resolvedTenant.isEmpty()
                && !resolvedTenant.equals(defaultTenant)) {
            return REDIRECT_ROOT + resolvedTenant + "/";
        }
        return REDIRECT_ROOT;
    }

    /**
     * Retrieve the MfaPendingAuthenticationToken from the session, or null if absent.
     *
     * @param request the HTTP request.
     * @return the pending token, or {@code null}.
     */
    private MfaPendingAuthenticationToken getPending(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return (MfaPendingAuthenticationToken) session.getAttribute(SESSION_MFA_PENDING);
    }

    /**
     * Determine the current username from the session pending token or SecurityContext.
     * Returns {@code null} for unauthenticated or anonymous users.
     *
     * @param request the HTTP request.
     * @return the username string, or {@code null} if not resolvable.
     */
    private String resolveUsername(HttpServletRequest request) {
        MfaPendingAuthenticationToken pending = getPending(request);
        if (pending != null) {
            return (String) pending.getPrincipal();
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null
                && auth.isAuthenticated()
                && !(auth instanceof org.springframework.security.authentication.AnonymousAuthenticationToken)) {
            return auth.getName();
        }
        return null;
    }

    /**
     * Resolve the effective tenant ID, preferring the path variable, then the session,
     * then falling back to the default tenant.
     *
     * @param pathTenantId tenant ID from the URL path variable (may be null).
     * @param request      the HTTP request (used to read from session).
     * @return the resolved non-null tenant ID.
     */
    private String resolveTenant(String pathTenantId, HttpServletRequest request) {
        if (pathTenantId != null && !pathTenantId.isEmpty()) {
            return pathTenantId;
        }
        HttpSession session = request.getSession(false);
        if (session != null) {
            String sessionTenant = (String) session.getAttribute(SESSION_MFA_TENANT);
            if (sessionTenant != null && !sessionTenant.isEmpty()) {
                return sessionTenant;
            }
        }
        return TenantUtils.getDefaultTenant();
    }

    /**
     * Build a redirect to the MFA enrollment setup page, tenant-aware.
     *
     * @param resolvedTenant the resolved tenant ID (may be null/default).
     * @return the redirect view string.
     */
    private String redirectToEnrollSetup(String resolvedTenant) {
        String defaultTenant = TenantUtils.getDefaultTenant();
        if (resolvedTenant != null && !resolvedTenant.isEmpty()
                && !resolvedTenant.equals(defaultTenant)) {
            return REDIRECT_ROOT + resolvedTenant + PATH_ENROLL_SETUP;
        }
        return REDIRECT_ENROLL_SETUP;
    }

    /**
     * Build a redirect to the MFA recovery options page, tenant-aware.
     *
     * @param resolvedTenant the resolved tenant ID (may be null/default).
     * @return the redirect view string.
     */
    private String redirectToRecovery(String resolvedTenant) {
        String defaultTenant = TenantUtils.getDefaultTenant();
        if (resolvedTenant != null && !resolvedTenant.isEmpty()
                && !resolvedTenant.equals(defaultTenant)) {
            return REDIRECT_ROOT + resolvedTenant + "/mfa/recovery";
        }
        return "redirect:/mfa/recovery";
    }
}
