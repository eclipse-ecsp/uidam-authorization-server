package org.eclipse.ecsp.oauth2.server.core.mfa;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MfaPolicyProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MfaPolicyProperties.MfaMode;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.InputSanitizer;
import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Filter inserted after CustomUserPwdAuthenticationFilter.
 *
 * <p>All MFA transient state that was previously held in {@code HttpSession} is now stored
 * in the shared database via {@link MfaStateService}, making this filter pod-affinity-free.
 *
 * <p>Logic:
 * <ol>
 *   <li>If the database already holds an {@code MFA_PENDING} record for this session
 *       → re-check live enrollment status: redirect to /{tenant}/mfa/challenge when the user is
 *       ACTIVE-enrolled, otherwise to /{tenant}/mfa/enroll/setup.</li>
 *   <li>If the user is fully authenticated AND MFA is enforced AND ACTIVE-enrolled
 *       → downgrade to MfaPendingAuthenticationToken (persisted to DB) and redirect to challenge.</li>
 *   <li>If the user is fully authenticated AND MFA is enforced AND NOT ACTIVE-enrolled
 *       → persist pending token and redirect to enrollment setup.</li>
 *   <li>Otherwise (MFA disabled, skip-listed user, or CONDITIONAL without step-up) pass through.</li>
 * </ol>
 */
public class MfaChallengeFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(MfaChallengeFilter.class);

    // These constants are kept for backward-compatibility with any code that still references them,
    // but they are NO LONGER used to read/write HttpSession attributes.
    static final String SESSION_MFA_PENDING  = "MFA_PENDING_AUTH";
    static final String SESSION_MFA_TENANT   = "MFA_TENANT_ID";
    static final String SESSION_MFA_VERIFIED = "MFA_VERIFIED_ONCE";

    private static final String MFA_PREFIX  = "/mfa";
    private static final String CSS_PREFIX  = "/css";
    private static final String IMG_PREFIX  = "/images";
    private static final String ACTUATOR    = "/actuator";
    private static final String FAVICON     = "/favicon";

    private static final int MIN_PATH_PARTS = 2;

    private final MfaSecretService mfaSecretService;
    private final TenantConfigurationService tenantConfigurationService;
    private final MfaStateService mfaStateService;

    /**
     * Constructs a MfaChallengeFilter.
     *
     * @param mfaSecretService           production MFA service for checking enrollment status.
     * @param tenantConfigurationService service for resolving the per-tenant MFA policy.
     * @param mfaStateService            stateless DB-backed MFA state manager.
     */
    public MfaChallengeFilter(MfaSecretService mfaSecretService,
                              TenantConfigurationService tenantConfigurationService,
                              MfaStateService mfaStateService) {
        this.mfaSecretService = mfaSecretService;
        this.tenantConfigurationService = tenantConfigurationService;
        this.mfaStateService = mfaStateService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String uri = request.getRequestURI();

        // Always allow MFA pages and static resources through
        if (isPassThrough(uri)) {
            LOGGER.debug("[MFA-FILTER] PASS-THROUGH (static/mfa/login path): {}", uri);
            chain.doFilter(request, response);
            return;
        }

        LOGGER.debug("[MFA-FILTER] >>> Evaluating URI: {}", uri);

        // --- MFA just completed: single-use DB flag consumed to let /oauth2/authorize through ---
        if (mfaStateService.consumeMfaVerified(request)) {
            LOGGER.info("[MFA-FILTER] MFA_VERIFIED_ONCE consumed – single-use pass-through: {}", uri);
            chain.doFilter(request, response);
            return;
        }

        // --- Case 1: MFA pending token already in DB (password OK, MFA not done) ---
        Optional<MfaPendingAuthenticationToken> pendingOpt = mfaStateService.loadPending(request);
        if (pendingOpt.isPresent()) {
            handlePendingFromDb(request, response, pendingOpt.get());
            return;
        }

        // --- Case 2 & 3: Fully authenticated user just passed password auth ---
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null) {
            LOGGER.info("[MFA-FILTER] No Authentication in SecurityContext for URI: {} – passing through", uri);
            chain.doFilter(request, response);
            return;
        }

        LOGGER.info("[MFA-FILTER] Auth class={} name={} authenticated={}",
                auth.getClass().getSimpleName(), auth.getName(), auth.isAuthenticated());

        if (auth.isAuthenticated() && !(auth instanceof MfaPendingAuthenticationToken)) {
            handleAuthenticatedUser(request, response, chain, auth);
        } else {
            LOGGER.info("[MFA-FILTER] Auth not fully authenticated or already pending – passing through");
            chain.doFilter(request, response);
        }
    }

    /**
     * Handle a request for which the DB already has a pending MFA token.
     * Re-checks the live enrollment status to route to challenge vs. enroll.
     */
    private void handlePendingFromDb(HttpServletRequest request, HttpServletResponse response,
                                     MfaPendingAuthenticationToken pending) throws IOException {
        String tenant = mfaStateService.loadTenant(request);
        String username = pending.getName();

        boolean enrolled = mfaSecretService.isEnrolled(username);
        String target = enrolled
                ? mfaPath(tenant, "/mfa/challenge")
                : mfaPath(tenant, "/mfa/enroll/setup");
        LOGGER.info("[MFA-FILTER] Case 1 – MFA_PENDING in DB for user='{}', enrolled={} → redirecting to: {}",
                username, enrolled, target);
        SecurityContextHolder.clearContext();
        response.sendRedirect(target);
    }

    /**
     * Handle a fully-authenticated user: apply the per-tenant MFA policy and either redirect
     * to MFA challenge, enrollment setup, or pass through.
     */
    private void handleAuthenticatedUser(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain, Authentication auth) throws ServletException, IOException {
        String username = auth.getName();
        String tenant = resolveTenantFromRequest(request);
        LOGGER.info("[MFA-FILTER] Resolved tenant='{}' for user='{}'", tenant, username);

        MfaPolicyProperties policy = resolveMfaPolicy(tenant);
        MfaMode mode = policy.getMode();
        LOGGER.info("[MFA-FILTER] Tenant '{}' MFA mode={} for user='{}'", tenant, mode, username);

        if (mode == MfaMode.DISABLED) {
            LOGGER.info("[MFA-FILTER] MFA DISABLED for tenant='{}' – passing through user='{}'", tenant, username);
            chain.doFilter(request, response);
            return;
        }

        if (policy.isUserSkipped(username)) {
            LOGGER.info("[MFA-FILTER] user='{}' is in MFA skip-list for tenant='{}' – passing through",
                    username, tenant);
            chain.doFilter(request, response);
            return;
        }

        String clientId = request.getParameter("client_id");
        if (policy.isClientSkipped(clientId)) {
            LOGGER.info("[MFA-FILTER] client_id='{}' is in MFA skip-list for tenant='{}' – passing through",
                    InputSanitizer.forLog(clientId), InputSanitizer.forLog(tenant));
            chain.doFilter(request, response);
            return;
        }

        String accountName = resolveAccountId(auth);
        if (policy.isAccountSkipped(accountName)) {
            LOGGER.info("[MFA-FILTER] accountId='{}' is in MFA skip-list for tenant='{}' – passing through",
                    accountName, tenant);
            chain.doFilter(request, response);
            return;
        }

        if (mode == MfaMode.CONDITIONAL && !requiresStepUp(request, auth, policy, clientId, accountName)) {
            LOGGER.info("[MFA-FILTER] CONDITIONAL mode and no step-up condition matched for user='{}' "
                    + "– passing through", username);
            chain.doFilter(request, response);
            return;
        }

        boolean enrolled = mfaSecretService.isEnrolled(username);
        LOGGER.info("[MFA-FILTER] Enforcing MFA – user='{}' enrolled={}", username, enrolled);

        if (enrolled) {
            handleEnrolledUser(request, response, auth, username, tenant);
        } else {
            redirectToEnrollSetup(request, response, auth, username, tenant);
        }
    }

    /**
     * Resolve the per-tenant MFA policy, falling back to a safe default (REQUIRED) if the
     * tenant or its policy cannot be resolved.
     */
    private MfaPolicyProperties resolveMfaPolicy(String tenant) {
        try {
            TenantProperties props = tenantConfigurationService.getTenantProperties(tenant);
            if (props != null && props.getMfa() != null) {
                return props.getMfa();
            }
        } catch (Exception ex) {
            LOGGER.warn("[MFA-FILTER] Could not resolve MFA policy for tenant='{}', defaulting to REQUIRED: {}",
                    tenant, ex.getMessage());
        }
        return new MfaPolicyProperties();
    }

    private boolean requiresStepUp(HttpServletRequest request, Authentication auth,
            MfaPolicyProperties policy, String clientId, String accountName) {

        // 0. Per-user MFA override: mfaRequired attribute from user-management (highest priority in CONDITIONAL)
        //    true  → always enforce MFA for this user
        //    false → always skip MFA for this user
        //    null  → no per-user override, continue to normal step-up rules
        if (auth instanceof CustomUserPwdAuthenticationToken customToken) {
            Boolean perUserMfa = customToken.getMfaRequired();
            if (perUserMfa != null) {
                LOGGER.info("[MFA-FILTER] CONDITIONAL per-user mfaRequired='{}' for user='{}' – overrides step-up",
                        perUserMfa, auth.getName());
                return perUserMfa;
            }
        }

        // 1. Step-up client check: if the requesting client_id is in the step-up list → enforce MFA
        Set<String> stepUpClients = policy.getStepUpClientSet();
        if (!stepUpClients.isEmpty() && clientId != null && !clientId.isBlank()) {
            boolean clientMatch = stepUpClients.stream().anyMatch(c -> c.equalsIgnoreCase(clientId));
            LOGGER.info("[MFA-FILTER] CONDITIONAL step-up check on client_id='{}' vs stepUpClients={} -> {}",
                    InputSanitizer.forLog(clientId), stepUpClients, clientMatch);
            if (clientMatch) {
                return true;
            }
        }

        // 2. Step-up account check: if the user's account ID (from user-management record) is in the step-up list
        Set<String> stepUpAccounts = policy.getStepUpAccountSet();
        if (!stepUpAccounts.isEmpty() && accountName != null && !accountName.isBlank()) {
            boolean accountMatch = stepUpAccounts.stream().anyMatch(a -> a.equalsIgnoreCase(accountName));
            LOGGER.info("[MFA-FILTER] CONDITIONAL step-up check on accountId='{}' vs stepUpAccounts={} -> {}",
                    accountName, stepUpAccounts, accountMatch);
            if (accountMatch) {
                return true;
            }
        }

        // 3. Step-up scope check (original behaviour)
        Set<String> stepUpScopes = policy.getStepUpScopeSet();
        if (stepUpScopes.isEmpty()) {
            LOGGER.info("[MFA-FILTER] CONDITIONAL mode but no step-up conditions configured – MFA not enforced");
            return false;
        }

        Set<String> requestedScopes = extractRequestedScopes(request);
        if (!requestedScopes.isEmpty()) {
            boolean match = requestedScopes.stream().anyMatch(stepUpScopes::contains);
            LOGGER.info("[MFA-FILTER] CONDITIONAL step-up check on requested scopes={} vs stepUp={} -> {}",
                    requestedScopes.stream().map(InputSanitizer::forLog).collect(Collectors.toSet()), stepUpScopes, match);
            return match;
        }

        Set<String> userScopes = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(MfaChallengeFilter::normalizeScope)
                .collect(Collectors.toSet());
        boolean match = userScopes.stream().anyMatch(stepUpScopes::contains);
        LOGGER.info("[MFA-FILTER] CONDITIONAL step-up check on user scopes={} vs stepUp={} -> {}",
                userScopes, stepUpScopes, match);
        return match;
    }

    /**
     * Extract the account ID from the {@link Authentication} token.
     * Returns the account ID sourced from the user-management service record
     * (populated in {@code CustomUserPwdAuthenticationToken} from
     * {@code UserDetailsResponse.getAccountId()}, same origin as the user's granted scopes).
     * Returns {@code null} for any other token type.
     */
    private String resolveAccountId(Authentication auth) {
        if (auth instanceof CustomUserPwdAuthenticationToken customToken) {
            return customToken.getAccountId();
        }
        return null;
    }

    private Set<String> extractRequestedScopes(HttpServletRequest request) {
        String scopeParam = request.getParameter("scope");
        if (scopeParam == null || scopeParam.isBlank()) {
            return new HashSet<>();
        }
        return Arrays.stream(scopeParam.trim().split("\\s+"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    private static String normalizeScope(String authority) {
        if (authority != null && authority.startsWith("SCOPE_")) {
            return authority.substring("SCOPE_".length());
        }
        return authority;
    }

    /** Enrolled user: persist pending token to DB and redirect to MFA challenge page. */
    private void handleEnrolledUser(HttpServletRequest request, HttpServletResponse response,
            Authentication auth, String username, String tenant) throws IOException {
        String target = mfaPath(tenant, "/mfa/challenge");
        LOGGER.info("[MFA-FILTER] MFA challenge required for user='{}' – redirecting to: {}", username, target);
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(username, auth.getAuthorities());
        mfaStateService.savePending(request, pending, tenant);
        SecurityContextHolder.clearContext();
        response.sendRedirect(target);
    }

    /** Not enrolled: persist pending token to DB and redirect to enrollment setup. */
    private void redirectToEnrollSetup(HttpServletRequest request, HttpServletResponse response,
            Authentication auth, String username, String tenant) throws IOException {
        String target = mfaPath(tenant, "/mfa/enroll/setup");
        LOGGER.info("[MFA-FILTER] First-time MFA enroll for user='{}' – redirecting to: {}", username, target);
        mfaStateService.savePending(request,
                new MfaPendingAuthenticationToken(username, auth.getAuthorities()), tenant);
        SecurityContextHolder.clearContext();
        response.sendRedirect(target);
    }

    /**
     * Build a tenant-aware MFA path.
     */
    static String mfaPath(String tenant, String path) {
        String defaultTenant = TenantUtils.getDefaultTenant();
        if (tenant != null && !tenant.isEmpty() && !tenant.equals(defaultTenant)) {
            return "/" + tenant + path;
        }
        return path;
    }

    /**
     * Resolve the tenant from the incoming request URI or fall back to the default tenant.
     */
    private String resolveTenantFromRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri != null && uri.startsWith("/")) {
            String[] parts = uri.split("/");
            if (parts.length >= MIN_PATH_PARTS) {
                String candidate = parts[1];
                if (!candidate.isEmpty()
                        && !candidate.equals("oauth2")
                        && !candidate.equals("login")
                        && !candidate.equals("mfa")
                        && !candidate.equals("css")
                        && !candidate.equals("images")
                        && !candidate.equals("actuator")) {
                    return candidate;
                }
            }
        }
        return TenantUtils.getDefaultTenant();
    }

    private boolean isPassThrough(String uri) {
        return uri.startsWith(MFA_PREFIX)
                || uri.contains("/mfa/")
                || uri.startsWith(CSS_PREFIX)
                || uri.startsWith(IMG_PREFIX)
                || uri.startsWith(ACTUATOR)
                || uri.startsWith(FAVICON)
                || uri.contains("login")
                || uri.contains("logout")
                || uri.contains(".well-known")
                || uri.contains("oauth2/token")
                || uri.contains("oauth2/jwks");
    }
}
