package org.eclipse.ecsp.oauth2.server.core.mfa;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MfaPolicyProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MfaPolicyProperties.MfaMode;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
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
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Filter inserted after CustomUserPwdAuthenticationFilter.
 *
 * <p>Logic:
 * <ol>
 *   <li>If the session already carries an {@code MFA_PENDING} marker
 *       → re-check live enrollment status: redirect to /{tenant}/mfa/challenge when the user is
 *       ACTIVE-enrolled, otherwise to /{tenant}/mfa/enroll/setup (covers abandoned enrollments
 *       that leave a stale PENDING marker).</li>
 *   <li>If the user is fully authenticated AND MFA is enforced AND ACTIVE-enrolled
 *       → downgrade to MfaPendingAuthenticationToken and redirect to /{tenant}/mfa/challenge.</li>
 *   <li>If the user is fully authenticated AND MFA is enforced AND NOT ACTIVE-enrolled
 *       (any non-ACTIVE status, including PENDING)
 *       → redirect to /{tenant}/mfa/enroll/setup so they can register; never pass through.</li>
 *   <li>Otherwise (MFA disabled, skip-listed user, or CONDITIONAL without step-up) pass through.</li>
 * </ol>
 */
public class MfaChallengeFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(MfaChallengeFilter.class);

    static final String SESSION_MFA_PENDING  = "MFA_PENDING_AUTH";
    /** Session key for persisting the resolved tenant ID across MFA redirect hops. */
    static final String SESSION_MFA_TENANT   = "MFA_TENANT_ID";
    /**
     * Session key set by MfaController after successful MFA completion.
     * Prevents MfaChallengeFilter from re-intercepting the /oauth2/authorize redirect
     * that immediately follows MFA, which would cause an infinite challenge loop.
     * Cleared on first use (single-use pass-through).
     */
    static final String SESSION_MFA_VERIFIED = "MFA_VERIFIED_ONCE";

    private static final String MFA_PREFIX  = "/mfa";
    private static final String CSS_PREFIX  = "/css";
    private static final String IMG_PREFIX  = "/images";
    private static final String ACTUATOR    = "/actuator";
    private static final String FAVICON     = "/favicon";

    private static final int  MIN_PATH_PARTS      = 2;

    private final MfaSecretService mfaSecretService;
    private final TenantConfigurationService tenantConfigurationService;

    /**
     * Constructs a MfaChallengeFilter.
     *
     * @param mfaSecretService           production MFA service for checking enrollment status.
     * @param tenantConfigurationService service for resolving the per-tenant MFA policy.
     */
    public MfaChallengeFilter(MfaSecretService mfaSecretService,
                              TenantConfigurationService tenantConfigurationService) {
        this.mfaSecretService = mfaSecretService;
        this.tenantConfigurationService = tenantConfigurationService;
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

        HttpSession session = request.getSession(false);
        boolean hasSession = session != null;
        LOGGER.debug("[MFA-FILTER] Session present={}", hasSession);
        // --- MFA just completed: single-use pass-through to let /oauth2/authorize through ---
        if (session != null && Boolean.TRUE.equals(session.getAttribute(SESSION_MFA_VERIFIED))) {
            session.removeAttribute(SESSION_MFA_VERIFIED); // consume immediately
            LOGGER.info("[MFA-FILTER] MFA_VERIFIED flag consumed – single-use pass-through: {}", uri);
            chain.doFilter(request, response);
            return;
        }

        // --- Case 1: MFA pending token already in session (password OK, MFA not done) ---
        if (session != null && session.getAttribute(SESSION_MFA_PENDING) != null) {
            handlePendingSession(session, response);
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
            return;
        } else if (auth instanceof MfaPendingAuthenticationToken) {
            LOGGER.info("[MFA-FILTER] Auth is MfaPendingAuthenticationToken"
                    + " (should have been caught by session check) - passing through");
        } else {
            LOGGER.info("[MFA-FILTER] Auth not fully authenticated (class={}) - passing through",
                    auth.getClass().getSimpleName());
        }

        chain.doFilter(request, response);
    }

    /**
     * Handle a request that already carries an {@code MFA_PENDING} marker in the session.
     *
     * <p>A pending marker can survive an abandoned enrollment (the user opened the enrollment
     * page and closed it without finishing). In that case the user is still NOT enrolled, so
     * routing them to the challenge page would be wrong. We therefore re-check the live
     * enrollment status and only show the challenge to ACTIVE-enrolled users; everyone else is
     * sent (back) to the enrollment page.
     *
     * @param session  the current HTTP session (guaranteed non-null, holds the pending marker)
     * @param response the HTTP response used to issue the redirect
     */
    private void handlePendingSession(HttpSession session, HttpServletResponse response) throws IOException {
        String tenant = (String) session.getAttribute(SESSION_MFA_TENANT);
        Object pending = session.getAttribute(SESSION_MFA_PENDING);
        String username = pending instanceof MfaPendingAuthenticationToken token ? token.getName() : null;

        boolean enrolled = username != null && mfaSecretService.isEnrolled(username);
        String target = enrolled
                ? mfaPath(tenant, "/mfa/challenge")
                : mfaPath(tenant, "/mfa/enroll/setup");
        LOGGER.info("[MFA-FILTER] Case 1 – MFA_PENDING in session for user='{}', enrolled={} → redirecting to: {}",
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

        // --- Policy gate 1: MFA disabled for the tenant ---
        if (mode == MfaMode.DISABLED) {
            LOGGER.info("[MFA-FILTER] MFA DISABLED for tenant='{}' – passing through user='{}'", tenant, username);
            chain.doFilter(request, response);
            return;
        }

        // --- Policy gate 2: user is in the skip-list (e.g. admin / service accounts) ---
        if (policy.isUserSkipped(username)) {
            LOGGER.info("[MFA-FILTER] user='{}' is in MFA skip-list for tenant='{}' – passing through",
                    username, tenant);
            chain.doFilter(request, response);
            return;
        }

        // --- Policy gate 3: CONDITIONAL mode only enforces when a step-up scope is requested ---
        if (mode == MfaMode.CONDITIONAL && !requiresStepUp(request, auth, policy)) {
            LOGGER.info("[MFA-FILTER] CONDITIONAL mode and no step-up scope matched for user='{}' "
                    + "– passing through", username);
            chain.doFilter(request, response);
            return;
        }

        boolean enrolled = mfaSecretService.isEnrolled(username);

        LOGGER.info("[MFA-FILTER] Enforcing MFA – user='{}' enrolled={}", username, enrolled);

        // Decision tree when MFA is enforced:
        //   enrolled=true  → challenge page
        //   enrolled=false → enrollment page (PENDING is treated the same as NOT_ENROLLED so
        //                    an abandoned enrollment never bypasses MFA via chain.doFilter()).
        if (enrolled) {
            handleEnrolledUser(request, response, auth, username, tenant);
        } else {
            redirectToEnrollSetup(request, response, auth, username, tenant);
        }
    }

    /**
     * Resolve the per-tenant MFA policy, falling back to a safe default (REQUIRED) if the
     * tenant or its policy cannot be resolved.
     *
     * @param tenant the resolved tenant ID
     * @return the effective {@link MfaPolicyProperties} (never {@code null})
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

    /**
     * Determine whether the current request requires an MFA step-up under CONDITIONAL mode.
     *
     * <p>The requested OAuth2 {@code scope} parameter is matched against the tenant's configured
     * step-up scopes. If the request carries no scopes (e.g. a portal login), the user's own
     * granted authorities/scopes are checked instead.
     *
     * @param request the current HTTP request
     * @param auth    the authenticated user
     * @param policy  the tenant MFA policy
     * @return {@code true} if MFA must be enforced for this request
     */
    private boolean requiresStepUp(HttpServletRequest request, Authentication auth, MfaPolicyProperties policy) {
        Set<String> stepUpScopes = policy.getStepUpScopeSet();
        if (stepUpScopes.isEmpty()) {
            // No step-up scopes configured for a CONDITIONAL tenant → nothing triggers MFA.
            LOGGER.info("[MFA-FILTER] CONDITIONAL mode but no step-up-scopes configured – MFA not enforced");
            return false;
        }

        Set<String> requestedScopes = extractRequestedScopes(request);
        if (!requestedScopes.isEmpty()) {
            boolean match = requestedScopes.stream().anyMatch(stepUpScopes::contains);
            LOGGER.info("[MFA-FILTER] CONDITIONAL step-up check on requested scopes={} vs stepUp={} -> {}",
                    requestedScopes, stepUpScopes, match);
            return match;
        }

        // No scopes on the request (e.g. portal login) → check all of the user's granted scopes.
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
     * Extract the requested OAuth2 scopes from the {@code scope} request parameter (space-delimited).
     *
     * @param request the current HTTP request
     * @return the set of requested scopes (possibly empty, never {@code null})
     */
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

    /**
     * Normalise a Spring Security authority into a bare scope name by stripping a leading
     * {@code SCOPE_} prefix if present.
     *
     * @param authority the granted authority string
     * @return the normalised scope
     */
    private static String normalizeScope(String authority) {
        if (authority != null && authority.startsWith("SCOPE_")) {
            return authority.substring("SCOPE_".length());
        }
        return authority;
    }

    /** Enrolled user: redirect to the MFA challenge page. */
    private void handleEnrolledUser(HttpServletRequest request, HttpServletResponse response,
            Authentication auth, String username, String tenant)
            throws IOException {
        String target = mfaPath(tenant, "/mfa/challenge");
        LOGGER.info("[MFA-FILTER] MFA challenge required for user='{}' – redirecting to: {}", username, target);
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(username, auth.getAuthorities());
        HttpSession newSession = request.getSession(true);
        newSession.setAttribute(SESSION_MFA_PENDING, pending);
        newSession.setAttribute(SESSION_MFA_TENANT, tenant);
        SecurityContextHolder.clearContext();
        response.sendRedirect(target);
    }

    /** Not enrolled and no pending enrollment: redirect to first-time enrollment setup. */
    private void redirectToEnrollSetup(HttpServletRequest request, HttpServletResponse response,
            Authentication auth, String username, String tenant) throws IOException {
        String target = mfaPath(tenant, "/mfa/enroll/setup");
        LOGGER.info("[MFA-FILTER] First-time MFA enroll for user='{}' – redirecting to: {}", username, target);
        HttpSession newSession = request.getSession(true);
        newSession.setAttribute(SESSION_MFA_PENDING,
                new MfaPendingAuthenticationToken(username, auth.getAuthorities()));
        newSession.setAttribute(SESSION_MFA_TENANT, tenant);
        SecurityContextHolder.clearContext();
        response.sendRedirect(target);
    }

    /**
     * Build a tenant-aware MFA path.
     * For default tenant or no tenant: returns the plain path.
     * For named tenant: returns /{tenant}{path}.
     *
     * @param tenant the resolved tenant ID (may be null).
     * @param path   the MFA path, e.g. "/mfa/challenge".
     * @return the fully-qualified redirect path.
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
     * For a URL like /{tenant}/login or /{tenant}/oauth2/authorize we read parts[1].
     *
     * @param request the current HTTP request.
     * @return the tenant ID string (never null).
     */
    private String resolveTenantFromRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri != null && uri.startsWith("/")) {
            String[] parts = uri.split("/");
            // parts[0] is empty, parts[1] is the first segment
            if (parts.length >= MIN_PATH_PARTS) {
                String candidate = parts[1];
                // If it looks like a tenant (not a known static/api segment), use it
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
