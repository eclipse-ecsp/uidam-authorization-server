package org.eclipse.ecsp.oauth2.server.core.mfa;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.ecsp.oauth2.server.core.entities.AuthorizationSecurityContext;
import org.eclipse.ecsp.oauth2.server.core.entities.MfaFlowState;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationSecurityContextRepository;
import org.eclipse.ecsp.oauth2.server.core.repositories.MfaFlowStateRepository;
import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Stateless (no HttpSession) manager for all transient MFA flow state.
 *
 * <p>All data that was previously stored in {@code HttpSession} attributes is now
 * persisted in the shared PostgreSQL database so that any pod can continue an
 * in-flight MFA flow started by a different pod.
 *
 * <h3>Data model</h3>
 * <ul>
 *   <li><b>MFA pending token</b> – username, authorities, and tenant stored as extra columns
 *       on the existing {@code authorization_security_context} row (keyed by session-cookie ID).</li>
 *   <li><b>MFA verified flag</b> – stored as a boolean column on the same row; consumed
 *       (reset to {@code false}) on first use to allow the follow-on
 *       {@code /oauth2/authorize} request through without re-interception.</li>
 *   <li><b>Recovery flow state</b> – stored in the {@code mfa_flow_state} table keyed by
 *       username; holds the last email-send timestamp (rate-limit) and the
 *       email-verification flag (guards backup-code step).</li>
 * </ul>
 */
@Service
public class MfaStateService {

    private static final Logger LOGGER = LoggerFactory.getLogger(MfaStateService.class);

    private static final String COMMA = ",";

    private final AuthorizationSecurityContextRepository securityContextRepo;
    private final MfaFlowStateRepository mfaFlowStateRepo;

    /**
     * Constructs the service with the required repositories.
     *
     * @param securityContextRepo repository for the authorization security context table
     * @param mfaFlowStateRepo    repository for the per-user MFA flow-state table
     */
    public MfaStateService(AuthorizationSecurityContextRepository securityContextRepo,
                           MfaFlowStateRepository mfaFlowStateRepo) {
        this.securityContextRepo = securityContextRepo;
        this.mfaFlowStateRepo    = mfaFlowStateRepo;
    }

    // ─────────────────────── Session ID helper ──────────────────────────────

    /**
     * Return the session ID from the current request's session cookie.
     * Creates a new session if one does not already exist (mirrors the pre-existing
     * behaviour of {@code request.getSession().getId()}).
     *
     * @param request the current HTTP request
     * @return the non-null session ID string
     */
    public String sessionId(HttpServletRequest request) {
        return request.getSession(true).getId();
    }

    // ─────────────────────── Pending-MFA token ──────────────────────────────

    /**
     * Persist the MFA pending token and resolved tenant ID into the shared database.
     * Called by {@code MfaChallengeFilter} immediately after downgrading a fully-authenticated
     * user to a pending state.
     *
     * @param request   the current HTTP request (used to derive the session ID)
     * @param pending   the pending authentication token
     * @param tenantId  the resolved tenant ID
     */
    public void savePending(HttpServletRequest request,
                            MfaPendingAuthenticationToken pending,
                            String tenantId) {
        String sid = sessionId(request);
        AuthorizationSecurityContext ctx = getOrCreateCtx(sid);
        ctx.setMfaPendingUsername(pending.getName());
        String authorities = pending.getPendingAuthorities().stream()
                .map(a -> a.getAuthority())
                .collect(Collectors.joining(COMMA));
        ctx.setMfaPendingAuthorities(authorities);
        ctx.setMfaTenant(tenantId);
        ctx.setMfaVerifiedOnce(Boolean.FALSE);
        ctx.setUpdatedDate(Timestamp.from(Instant.now()));
        securityContextRepo.save(ctx);
        LOGGER.debug("[MFA-STATE] Saved pending token for session='{}' user='{}' tenant='{}'",
                sid, pending.getName(), tenantId);
    }

    /**
     * Load the MFA pending token from the database for the current session.
     *
     * @param request the current HTTP request
     * @return an {@link Optional} containing the token, or empty if no pending MFA exists
     */
    public Optional<MfaPendingAuthenticationToken> loadPending(HttpServletRequest request) {
        String sid = sessionId(request);
        return securityContextRepo.findBySessionId(sid)
                .filter(ctx -> StringUtils.isNotBlank(ctx.getMfaPendingUsername()))
                .map(ctx -> {
                    List<SimpleGrantedAuthority> authorities = Collections.emptyList();
                    if (StringUtils.isNotBlank(ctx.getMfaPendingAuthorities())) {
                        authorities = Arrays.stream(ctx.getMfaPendingAuthorities().split(COMMA))
                                .filter(StringUtils::isNotBlank)
                                .map(SimpleGrantedAuthority::new)
                                .toList();
                    }
                    return new MfaPendingAuthenticationToken(ctx.getMfaPendingUsername(), authorities);
                });
    }

    /**
     * Retrieve the persisted tenant ID for the current session's MFA flow.
     *
     * @param request the current HTTP request
     * @return the tenant ID, or the system-default tenant if not found
     */
    public String loadTenant(HttpServletRequest request) {
        String sid = sessionId(request);
        return securityContextRepo.findBySessionId(sid)
                .map(AuthorizationSecurityContext::getMfaTenant)
                .filter(StringUtils::isNotBlank)
                .orElseGet(TenantUtils::getDefaultTenant);
    }

    /**
     * Clear the pending MFA token and associated tenant from the database once
     * the challenge is satisfied (or abandoned).
     *
     * @param request the current HTTP request
     */
    public void clearPending(HttpServletRequest request) {
        String sid = sessionId(request);
        securityContextRepo.findBySessionId(sid).ifPresent(ctx -> {
            ctx.setMfaPendingUsername(null);
            ctx.setMfaPendingAuthorities(null);
            ctx.setMfaTenant(null);
            ctx.setMfaVerifiedOnce(Boolean.FALSE);
            ctx.setUpdatedDate(Timestamp.from(Instant.now()));
            securityContextRepo.save(ctx);
            LOGGER.debug("[MFA-STATE] Cleared pending token for session='{}'", sid);
        });
    }

    // ─────────────────────── MFA verified once ──────────────────────────────

    /**
     * Mark MFA as just-completed for this session.
     * {@code MfaChallengeFilter} will consume this flag on the very next
     * {@code /oauth2/authorize} request to avoid re-intercepting the redirect.
     *
     * @param request the current HTTP request
     */
    public void setMfaVerified(HttpServletRequest request) {
        String sid = sessionId(request);
        AuthorizationSecurityContext ctx = getOrCreateCtx(sid);
        ctx.setMfaVerifiedOnce(Boolean.TRUE);
        ctx.setUpdatedDate(Timestamp.from(Instant.now()));
        securityContextRepo.save(ctx);
        LOGGER.debug("[MFA-STATE] MFA_VERIFIED_ONCE set for session='{}'", sid);
    }

    /**
     * Check and atomically consume the MFA-verified flag.
     * Returns {@code true} only if the flag was set; resets it to {@code false} afterwards.
     *
     * @param request the current HTTP request
     * @return {@code true} if MFA was just completed and the flag was present
     */
    public boolean consumeMfaVerified(HttpServletRequest request) {
        String sid = sessionId(request);
        Optional<AuthorizationSecurityContext> optCtx = securityContextRepo.findBySessionId(sid);
        if (optCtx.isPresent()) {
            AuthorizationSecurityContext ctx = optCtx.get();
            if (Boolean.TRUE.equals(ctx.getMfaVerifiedOnce())) {
                ctx.setMfaVerifiedOnce(Boolean.FALSE);
                ctx.setUpdatedDate(Timestamp.from(Instant.now()));
                securityContextRepo.save(ctx);
                LOGGER.debug("[MFA-STATE] Consumed MFA_VERIFIED_ONCE for session='{}'", sid);
                return true;
            }
        }
        return false;
    }

    // ─────────────────────── Recovery flow state ────────────────────────────

    /**
     * Record that a recovery-key email was just sent to the given user.
     *
     * @param username the user's username
     */
    public void markRecoverySent(String username) {
        MfaFlowState state = getOrCreateFlowState(username);
        state.setRecoverySentAt(Timestamp.from(Instant.now()));
        state.setUpdatedDate(Timestamp.from(Instant.now()));
        mfaFlowStateRepo.save(state);
    }

    /**
     * Return the timestamp (epoch-ms) when the recovery email was last sent, or
     * {@code null} if no email has been sent.
     *
     * @param username the user's username
     * @return the send-timestamp, or {@code null}
     */
    public Long getRecoverySentAt(String username) {
        return mfaFlowStateRepo.findById(username)
                .map(MfaFlowState::getRecoverySentAt)
                .map(Timestamp::getTime)
                .orElse(null);
    }

    /**
     * Mark the email recovery key as verified for this user.
     * Gates the backup-code entry step in the recovery flow.
     *
     * @param username the user's username
     */
    public void markRecoveryEmailVerified(String username) {
        MfaFlowState state = getOrCreateFlowState(username);
        state.setRecoveryEmailVerified(Boolean.TRUE);
        state.setUpdatedDate(Timestamp.from(Instant.now()));
        mfaFlowStateRepo.save(state);
    }

    /**
     * Return whether the email recovery key has been verified for this user.
     *
     * @param username the user's username
     * @return {@code true} if the email key was verified
     */
    public boolean isRecoveryEmailVerified(String username) {
        return mfaFlowStateRepo.findById(username)
                .map(MfaFlowState::getRecoveryEmailVerified)
                .orElse(Boolean.FALSE);
    }

    /**
     * Clear all recovery-flow state for this user (called after the flow completes or is abandoned).
     *
     * @param username the user's username
     */
    public void clearRecoveryState(String username) {
        mfaFlowStateRepo.findById(username).ifPresent(state -> {
            state.setRecoverySentAt(null);
            state.setRecoveryEmailVerified(Boolean.FALSE);
            state.setUpdatedDate(Timestamp.from(Instant.now()));
            mfaFlowStateRepo.save(state);
        });
    }

    // ─────────────────────── Private helpers ────────────────────────────────

    private AuthorizationSecurityContext getOrCreateCtx(String sessionId) {
        return securityContextRepo.findBySessionId(sessionId).orElseGet(() -> {
            AuthorizationSecurityContext ctx = new AuthorizationSecurityContext();
            ctx.setSessionId(sessionId);
            Timestamp now = Timestamp.from(Instant.now());
            ctx.setCreatedDate(now);
            ctx.setUpdatedDate(now);
            ctx.setAuthenticated(Boolean.FALSE);
            // Required NOT NULL columns – placeholders until the full auth record is written.
            ctx.setPrincipal("mfa-pending");
            return ctx;
        });
    }

    private MfaFlowState getOrCreateFlowState(String username) {
        return mfaFlowStateRepo.findById(username).orElseGet(() -> {
            MfaFlowState state = new MfaFlowState();
            state.setUsername(username);
            Timestamp now = Timestamp.from(Instant.now());
            state.setCreatedDate(now);
            state.setUpdatedDate(now);
            state.setRecoveryEmailVerified(Boolean.FALSE);
            return state;
        });
    }
}
