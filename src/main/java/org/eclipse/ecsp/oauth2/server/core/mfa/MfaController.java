package org.eclipse.ecsp.oauth2.server.core.mfa;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.audit.context.HttpRequestContext;
import org.eclipse.ecsp.oauth2.server.core.audit.context.UserActorContext;
import org.eclipse.ecsp.oauth2.server.core.audit.enums.AuditEventType;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.metrics.MetricType;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.InputSanitizer;
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

/**
 * Handles all /mfa/** and /{tenantId}/mfa/** endpoints for the MFA (TOTP) login, enrollment,
 * and recovery flows.
 *
 * <p><strong>No HttpSession dependency.</strong>  All transient MFA state is stored in the
 * shared database via {@link MfaStateService} so that the flow works correctly in a
 * multi-pod (stateless) deployment.
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
    private static final String COMPONENT_NAME = "UIDAM_AUTHORIZATION_SERVER";

    private static final String REDIRECT_PREFIX       = "redirect:";
    private static final String REDIRECT_LOGIN        = REDIRECT_PREFIX + "/login";
    private static final String REDIRECT_ROOT         = REDIRECT_PREFIX + "/";
    private static final String PATH_ENROLL_SETUP     = "/mfa/enroll/setup";
    private static final String REDIRECT_ENROLL_SETUP = REDIRECT_PREFIX + PATH_ENROLL_SETUP;
    private static final String ATTR_USERNAME         = "username";
    private static final String ATTR_ERROR            = "error";
    private static final String ATTR_SECRET           = "secret";
    private static final String ATTR_MANUAL_KEY       = "manualKey";
    private static final String ATTR_QR_BASE64        = "qrBase64";
    private static final String ATTR_TENANT           = "tenantId";
    private static final String ATTR_APP_NAME         = "appName";

    private static final String VIEW_ENROLL_SETUP        = "mfa/mfa-enroll-setup";
    private static final String VIEW_ENROLL_BACKUP_CODES = "mfa/mfa-enroll-backup-codes";
    private static final String VIEW_CHALLENGE           = "mfa/mfa-challenge";
    private static final String VIEW_RECOVERY            = "mfa/mfa-recovery";
    private static final String VIEW_RECOVERY_BACKUP     = "mfa/mfa-recovery-backup";
    private static final String VIEW_RECOVERY_VERIFY     = "mfa/mfa-recovery-verify";
    private static final String VIEW_ERROR               = "mfa/mfa-error";

    private static final String ATTR_BACKUP_CODES     = "backupCodes";
    private static final String ATTR_REMAINING_CODES  = "remainingBackupCodes";
    private static final String ATTR_RESEND_COOLDOWN  = "resendCooldownSeconds";
    private static final String ATTR_EMAIL_SENT       = "emailSent";
    private static final String ERR_RECOVERY_EMAIL_SEND =
            "Unable to send the recovery code to your email. Please try again later or contact your administrator.";
    private static final long MILLIS_PER_SECOND = 1000L;

    private final MfaSecretService mfaSecretService;
    private final TotpService totpService;
    private final MfaProperties mfaProperties;
    private final TenantConfigurationService tenantConfigurationService;
    private final MfaStateService mfaStateService;
    private final AuditLogger auditLogger;
    private final AuthorizationMetricsService metricsService;

    /**
     * Constructs an MfaController.
     *
     * @param mfaSecretService           production MFA secret service.
     * @param totpService                TOTP utility service.
     * @param mfaProperties              MFA configuration properties.
     * @param tenantConfigurationService service for tenant-specific configuration.
     * @param mfaStateService            DB-backed stateless MFA flow-state manager.
     */
    public MfaController(MfaSecretService mfaSecretService,
                         TotpService totpService,
                         MfaProperties mfaProperties,
                         TenantConfigurationService tenantConfigurationService,
                         MfaStateService mfaStateService,
                         AuditLogger auditLogger,
                         AuthorizationMetricsService metricsService) {
        this.mfaSecretService           = mfaSecretService;
        this.totpService                = totpService;
        this.mfaProperties              = mfaProperties;
        this.tenantConfigurationService = tenantConfigurationService;
        this.mfaStateService            = mfaStateService;
        this.auditLogger                = auditLogger;
        this.metricsService             = metricsService;
    }

    // ──────────────────────── Model attribute ──────────────────────────────

    @org.springframework.web.bind.annotation.ModelAttribute(ATTR_APP_NAME)
    public String populateAppName() {
        return resolveMfaAppName();
    }

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

    private boolean isBackupCodesEnabled(String username) {
        return mfaSecretService.isBackupCodesEnabled(username);
    }

    // ─────────────────────────── ENROLLMENT ────────────────────────────────

    /**
     * Show the MFA enrollment setup page with a QR code.
     * Handles both /{tenantId}/mfa/enroll/setup and /mfa/enroll/setup.
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

        // Initiate enrollment in user-management: generates secret, stores as PENDING.
        // The secret is NEVER stored in the auth-server (no session, no DB column here).
        MfaEnrollInitiateResponseDto enrollData = mfaSecretService.initiateEnrollment(username);
        String secret = enrollData.secret();

        // Keep pending token & tenant current in the DB (in case this is a re-visit).
        MfaPendingAuthenticationToken pending = mfaStateService.loadPending(request)
                .orElseGet(() -> new MfaPendingAuthenticationToken(username, Collections.emptyList()));
        mfaStateService.savePending(request, pending, resolvedTenant);

        final String manualKey = enrollData.manualKey() != null
                ? enrollData.manualKey() : totpService.formatManualKey(secret);
        final String qrBase64  = totpService.generateQrCodeBase64FromUri(enrollData.qrUri());

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("[MFA] Enrollment setup tenant='{}' user='{}'",
                    InputSanitizer.forLog(resolvedTenant), InputSanitizer.forLog(username));
        }

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
     * <p>The TOTP secret is fetched live from user-management (it is in PENDING status),
     * so no session/DB storage on the auth-server side is needed.
     */
    @PostMapping({"/{tenantId}/mfa/enroll/verify", "/mfa/enroll/verify"})
    public String enrollVerify(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            @RequestParam("totpCode") String totpCode,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        String resolvedTenant = resolveTenant(tenantId, request);
        String username = resolveUsername(request);

        if (username == null) {
            LOGGER.warn("[MFA] /mfa/enroll/verify – no username resolvable, redirecting to login");
            return REDIRECT_LOGIN;
        }

        // Fetch the PENDING secret from user-management (no auth-server session needed).
        String secret = mfaSecretService.getSecret(username).orElse(null);
        if (secret == null) {
            model.addAttribute(ATTR_ERROR, "Enrollment session expired. Please try again.");
            return VIEW_ERROR;
        }

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("[MFA] Enrollment verify tenant='{}' user='{}'",
                    InputSanitizer.forLog(resolvedTenant), InputSanitizer.forLog(username));
        }

        if (totpService.validateCode(username, secret, totpCode)) {
            mfaSecretService.activateEnrollment(username);
            LOGGER.info("[MFA] Enrollment VERIFIED for user='{}'", username);
            recordAudit(AuditEventType.MFA_ENROLLMENT_COMPLETED, AuditEventResult.SUCCESS, username, request);
            recordMetric(MetricType.MFA_ENROLLMENT_SUCCESS, resolvedTenant);

            model.addAttribute(ATTR_TENANT, resolvedTenant);

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
            // Stash username+tenant in DB so backup-codes confirm can read it without session.
            MfaPendingAuthenticationToken pending = mfaStateService.loadPending(request)
                    .orElseGet(() -> new MfaPendingAuthenticationToken(username, Collections.emptyList()));
            mfaStateService.savePending(request, pending, resolvedTenant);
            return VIEW_ENROLL_BACKUP_CODES;
        }

        LOGGER.warn("[MFA] Enrollment verification FAILED for user='{}'", username);
        recordAudit(AuditEventType.MFA_ENROLLMENT_VERIFY_FAILED, AuditEventResult.FAILURE, username, request);
        recordMetric(MetricType.MFA_ENROLLMENT_FAILURE, resolvedTenant);
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
     */
    @PostMapping({"/{tenantId}/mfa/enroll/backup-codes/confirm", "/mfa/enroll/backup-codes/confirm"})
    public String backupCodesConfirm(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        // Load username and tenant from DB-backed state (no session required).
        String username = mfaStateService.loadPending(request)
                .map(p -> (String) p.getPrincipal())
                .orElse(null);

        if (username == null) {
            model.addAttribute(ATTR_ERROR, "Session expired. Please log in again.");
            return VIEW_ERROR;
        }

        String storedTenant = mfaStateService.loadTenant(request);
        String resolvedTenant = resolveTenant(
                storedTenant != null ? storedTenant : tenantId, request);

        mfaStateService.clearPending(request);
        return completeLogin(username, resolvedTenant, request, response);
    }

    // ─────────────────────────── CHALLENGE ─────────────────────────────────

    /**
     * Display the TOTP code entry page.
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
        model.addAttribute(ATTR_TENANT,   resolvedTenant);
        model.addAttribute(ATTR_USERNAME, pending.getPrincipal());
        return VIEW_CHALLENGE;
    }

    /**
     * Validate the submitted TOTP code and complete login on success.
     */
    @PostMapping({"/{tenantId}/mfa/challenge", "/mfa/challenge"})
    public String challengeSubmit(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            @RequestParam("totpCode") String totpCode,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        MfaPendingAuthenticationToken pending = getPending(request);
        if (pending == null) {
            return REDIRECT_LOGIN;
        }

        String resolvedTenant = resolveTenant(tenantId, request);
        String username = (String) pending.getPrincipal();
        String secret   = mfaSecretService.getSecret(username).orElse(null);

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("[MFA] Challenge attempt tenant='{}' user='{}'",
                    InputSanitizer.forLog(resolvedTenant), InputSanitizer.forLog(username));
        }

        if (secret != null && totpService.validateCode(username, secret, totpCode)) {
            recordAudit(AuditEventType.MFA_CHALLENGE_SUCCESS, AuditEventResult.SUCCESS, username, request);
            recordMetric(MetricType.MFA_CHALLENGE_SUCCESS, resolvedTenant);
            mfaStateService.clearPending(request);
            return completeLogin(username, resolvedTenant, request, response);
        }

        LOGGER.warn("[MFA] Challenge FAILED for user='{}'", username);
        recordAudit(AuditEventType.MFA_CHALLENGE_FAILURE, AuditEventResult.FAILURE, username, request);
        recordMetric(MetricType.MFA_CHALLENGE_FAILURE, resolvedTenant);
        model.addAttribute(ATTR_TENANT,   resolvedTenant);
        model.addAttribute(ATTR_USERNAME, username);
        model.addAttribute(ATTR_ERROR,    "Invalid code. Please try again.");
        return VIEW_CHALLENGE;
    }

    // ─────────────────────────── RE-ENROLL ─────────────────────────────────

    /**
     * Revoke the current user's MFA enrollment and redirect to setup.
     */
    @GetMapping({"/{tenantId}/mfa/re-enroll", "/mfa/re-enroll"})
    @SuppressWarnings({"java:S5146", "javasecurity:S5146", "javasecurity:S5145"})
    public String reEnroll(
            @PathVariable(value = "tenantId", required = false) String pathTenantId,
            @RequestParam(value = "tenantId", required = false) String paramTenantId,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

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
     * Display the recovery options page.
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
        model.addAttribute(ATTR_TENANT,         resolvedTenant);
        model.addAttribute(ATTR_USERNAME,        username);
        model.addAttribute(ATTR_REMAINING_CODES, 0);
        return VIEW_RECOVERY;
    }

    /**
     * Send the recovery email and redirect to the verification page.
     * Rate-limiting is enforced via the DB-backed {@link MfaStateService}.
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

        // Rate-limit: check cooldown from DB
        Long lastSentAt = mfaStateService.getRecoverySentAt(username);
        int cooldown = mfaProperties.getRecovery().getResendCooldownSeconds();
        if (lastSentAt != null) {
            long elapsed = (System.currentTimeMillis() - lastSentAt) / MILLIS_PER_SECOND;
            if (elapsed < cooldown) {
                model.addAttribute(ATTR_TENANT,          resolvedTenant);
                model.addAttribute(ATTR_USERNAME,        username);
                model.addAttribute(ATTR_RESEND_COOLDOWN, cooldown);
                model.addAttribute(ATTR_ERROR,
                        "Please wait " + (cooldown - elapsed) + " seconds before requesting a new code.");
                return VIEW_RECOVERY_VERIFY;
            }
        }

        try {
            mfaSecretService.sendRecoveryKey(username);
            mfaStateService.markRecoverySent(username);  // persist timestamp to DB
        } catch (org.springframework.security.oauth2.core.OAuth2AuthenticationException oauthEx) {
            LOGGER.error("[MFA] Failed to send recovery email for user='{}': {}", username, oauthEx.getMessage());
            model.addAttribute(ATTR_TENANT,   resolvedTenant);
            model.addAttribute(ATTR_USERNAME, username);
            model.addAttribute(ATTR_ERROR,    ERR_RECOVERY_EMAIL_SEND);
            return VIEW_RECOVERY;
        } catch (Exception ex) {
            LOGGER.error("[MFA] Failed to send recovery email for user='{}': {}", username, ex.getMessage());
            model.addAttribute(ATTR_TENANT,   resolvedTenant);
            model.addAttribute(ATTR_USERNAME, username);
            model.addAttribute(ATTR_ERROR,    ERR_RECOVERY_EMAIL_SEND);
            return VIEW_RECOVERY;
        }

        model.addAttribute(ATTR_TENANT,          resolvedTenant);
        model.addAttribute(ATTR_USERNAME,        username);
        model.addAttribute(ATTR_RESEND_COOLDOWN, cooldown);
        model.addAttribute(ATTR_EMAIL_SENT,
                "A security code has been sent to your registered email address.");
        return VIEW_RECOVERY_VERIFY;
    }

    /**
     * Verify the 6-character recovery key submitted by the user.
     * On success: revoke enrollment and redirect to re-enrollment (or backup-code step).
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

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("[MFA] Recovery key verification attempt for user='{}' tenant='{}'",
                    InputSanitizer.forLog(username), InputSanitizer.forLog(resolvedTenant));
        }

        boolean valid = mfaSecretService.verifyRecoveryKeyAndRevoke(username, recoveryKey);
        if (valid) {
            LOGGER.info("[MFA] Recovery key verified – enrollment revoked for user='{}'", username);
            recordAudit(AuditEventType.MFA_RECOVERY_COMPLETED, AuditEventResult.SUCCESS, username, request);
            recordMetric(MetricType.MFA_RECOVERY_SUCCESS, resolvedTenant);

            // Clear rate-limit state from DB
            mfaStateService.clearRecoveryState(username);

            if (isBackupCodesEnabled(username)) {
                // Persist email-verified flag to DB (no session)
                mfaStateService.markRecoveryEmailVerified(username);
                LOGGER.info("[MFA] Email recovery verified – prompting for backup code for user='{}'", username);
                model.addAttribute(ATTR_TENANT,   resolvedTenant);
                model.addAttribute(ATTR_USERNAME, username);
                return VIEW_RECOVERY_BACKUP;
            }

            return redirectToEnrollSetup(resolvedTenant);
        }

        LOGGER.warn("[MFA] Recovery key verification FAILED for user='{}'", username);
        recordAudit(AuditEventType.MFA_RECOVERY_FAILED, AuditEventResult.FAILURE, username, request);
        model.addAttribute(ATTR_TENANT,          resolvedTenant);
        model.addAttribute(ATTR_USERNAME,        username);
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
        String username = (String) pending.getPrincipal();
        if (!isBackupCodesEnabled(username)) {
            LOGGER.warn("[MFA] Backup-code recovery requested but feature is disabled");
            return redirectToRecovery(resolveTenant(tenantId, request));
        }
        model.addAttribute(ATTR_TENANT,   resolveTenant(tenantId, request));
        model.addAttribute(ATTR_USERNAME, username);
        return VIEW_RECOVERY_BACKUP;
    }

    /**
     * Submit a backup code for validation as the second step of account recovery.
     *
     * <p>Reachable only after the email recovery key has been verified
     * (guarded by {@link MfaStateService#isRecoveryEmailVerified(String)}).
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

        // Ensure the email recovery key was verified first (read from DB, no session).
        if (!mfaStateService.isRecoveryEmailVerified(username)) {
            LOGGER.warn("[MFA] Backup-code recovery without prior email verification for user='{}'", username);
            return redirectToRecovery(resolvedTenant);
        }

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("[MFA] Backup-code recovery attempt for user='{}' tenant='{}'",
                    InputSanitizer.forLog(username), InputSanitizer.forLog(resolvedTenant));
        }

        MfaBackupCodeVerifyResponseDto result = mfaSecretService.verifyBackupCode(username, backupCode);
        if (result != null && result.valid()) {
            LOGGER.info("[MFA] Backup-code verified for user='{}', remaining={}",
                    username, result.remainingBackupCodes());
            recordAudit(AuditEventType.MFA_BACKUP_CODE_USED, AuditEventResult.SUCCESS, username, request);
            recordMetric(MetricType.MFA_BACKUP_CODE_USED, resolvedTenant);

            mfaStateService.clearRecoveryState(username);    // clears email-verified flag in DB
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
     */
    @GetMapping({"/{tenantId}/mfa/recovery/continue", "/mfa/recovery/continue"})
    public String recoveryContinue(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        final String resolvedTenant = resolveTenant(tenantId, request);

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
     * After recovery success, user clicks "Re-enroll now".
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
     * Restore a full authenticated token into the security context and resume the OAuth2 flow.
     * The pending token is read from the DB (no session); tenant is resolved from the DB or URL.
     */
    private String completeLogin(String username, String resolvedTenant,
                                 HttpServletRequest request, HttpServletResponse response) {

        MfaPendingAuthenticationToken pending = getPending(request);

        UsernamePasswordAuthenticationToken fullAuth =
                new UsernamePasswordAuthenticationToken(
                        username, null,
                        pending != null ? pending.getPendingAuthorities() : Collections.emptyList());

        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(fullAuth);
        SecurityContextHolder.setContext(ctx);
        // Write the full authentication into the shared DB security context repo so other
        // Spring Security components can find it on the same (or a different) pod.
        request.getSession(true).setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, ctx);

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("[MFA] Login completed tenant='{}' user='{}' – resuming OAuth flow",
                    InputSanitizer.forLog(resolvedTenant), InputSanitizer.forLog(username));
        }

        // Mark MFA verified in DB so MfaChallengeFilter does not re-intercept the
        // upcoming /oauth2/authorize redirect and loop back to challenge.
        mfaStateService.setMfaVerified(request);

        CookieRequestCache requestCache = new CookieRequestCache();
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            String redirectUrl = savedRequest.getRedirectUrl();
            LOGGER.info("[MFA] Resuming saved OAuth2 request: {}", redirectUrl);
            requestCache.removeRequest(request, response);
            return REDIRECT_PREFIX + redirectUrl;
        }

        LOGGER.warn("[MFA] No saved OAuth2 request found, redirecting to root");
        String defaultTenant = TenantUtils.getDefaultTenant();
        if (resolvedTenant != null && !resolvedTenant.isEmpty()
                && !resolvedTenant.equals(defaultTenant)) {
            return REDIRECT_ROOT + resolvedTenant + "/";
        }
        return REDIRECT_ROOT;
    }

    /**
     * Retrieve the MfaPendingAuthenticationToken from the DB for this session, or null.
     */
    private MfaPendingAuthenticationToken getPending(HttpServletRequest request) {
        return mfaStateService.loadPending(request).orElse(null);
    }

    /**
     * Determine the current username from the DB pending token or SecurityContext.
     * Returns {@code null} for unauthenticated or anonymous users.
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
     * Resolve the effective tenant ID: path variable → DB tenant → default.
     */
    @SuppressWarnings({"java:S5146", "javasecurity:S5146", "javasecurity:S5145"})
    private String resolveTenant(String pathTenantId, HttpServletRequest request) {
        if (pathTenantId != null && !pathTenantId.isEmpty()) {
            return pathTenantId;
        }
        String dbTenant = mfaStateService.loadTenant(request);
        if (dbTenant != null && !dbTenant.isEmpty()) {
            return dbTenant;
        }
        return TenantUtils.getDefaultTenant();
    }

    private String redirectToEnrollSetup(String resolvedTenant) {
        String defaultTenant = TenantUtils.getDefaultTenant();
        if (resolvedTenant != null && !resolvedTenant.isEmpty()
                && !resolvedTenant.equals(defaultTenant)) {
            return REDIRECT_ROOT + resolvedTenant + PATH_ENROLL_SETUP;
        }
        return REDIRECT_ENROLL_SETUP;
    }

    private String redirectToRecovery(String resolvedTenant) {
        String defaultTenant = TenantUtils.getDefaultTenant();
        if (resolvedTenant != null && !resolvedTenant.isEmpty()
                && !resolvedTenant.equals(defaultTenant)) {
            return REDIRECT_ROOT + resolvedTenant + "/mfa/recovery";
        }
        return "redirect:/mfa/recovery";
    }

    /**
     * Records an MFA audit event. Never throws — failures are logged and swallowed so the
     * main authentication flow is never disrupted by an audit subsystem error.
     */
    private void recordAudit(AuditEventType eventType, AuditEventResult result,
                             String username, HttpServletRequest request) {
        try {
            UserActorContext actorContext = UserActorContext.builder()
                    .username(username)
                    .build();
            HttpRequestContext requestContext = HttpRequestContext.from(request);
            auditLogger.log(
                    eventType.getType(),
                    COMPONENT_NAME,
                    result,
                    eventType.getDescription(),
                    actorContext,
                    requestContext
            );
        } catch (Exception ex) {
            LOGGER.error("[MFA] Failed to record audit event {}: {}", eventType, ex.getMessage(), ex);
        }
    }

    /**
     * Increments an MFA metric counter for the given tenant. Never throws.
     */
    private void recordMetric(MetricType metricType, String tenantId) {
        try {
            metricsService.incrementMetricsForTenant(tenantId, metricType);
        } catch (Exception ex) {
            LOGGER.error("[MFA] Failed to record metric {}: {}", metricType, ex.getMessage(), ex);
        }
    }
}
