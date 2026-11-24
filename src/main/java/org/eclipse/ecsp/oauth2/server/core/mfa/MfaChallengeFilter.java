package org.eclipse.ecsp.oauth2.server.core.mfa;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MfaPolicyProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MfaPolicyProperties.MfaMode;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.metrics.MetricType;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils;
import org.eclipse.ecsp.oauth2.server.core.utils.InputSanitizer;
import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
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
    private final AuthorizationMetricsService metricsService;
    private final RegisteredClientRepository registeredClientRepository;

    /**
     * Constructs a MfaChallengeFilter without client lookup; OIDC-only step-up checks then consider every
     * user scope.
     *
     * @param mfaSecretService           production MFA service for checking enrollment status.
     * @param tenantConfigurationService service for resolving the per-tenant MFA policy.
     * @param mfaStateService            stateless DB-backed MFA state manager.
     */
    public MfaChallengeFilter(MfaSecretService mfaSecretService,
                              TenantConfigurationService tenantConfigurationService,
                              MfaStateService mfaStateService,
                              AuthorizationMetricsService metricsService) {
        this(mfaSecretService, tenantConfigurationService, mfaStateService, metricsService, null);
    }

    /**
     * Constructs a MfaChallengeFilter.
     *
     * @param mfaSecretService           production MFA service for checking enrollment status.
     * @param tenantConfigurationService service for resolving the per-tenant MFA policy.
     * @param mfaStateService            stateless DB-backed MFA state manager.
     * @param registeredClientRepository client lookup, used to limit OIDC-only step-up checks to scopes the
     *                                   token can actually receive.
     */
    public MfaChallengeFilter(MfaSecretService mfaSecretService,
                              TenantConfigurationService tenantConfigurationService,
                              MfaStateService mfaStateService,
                              AuthorizationMetricsService metricsService,
                              RegisteredClientRepository registeredClientRepository) {
        this.mfaSecretService = mfaSecretService;
        this.tenantConfigurationService = tenantConfigurationService;
        this.mfaStateService = mfaStateService;
        this.metricsService = metricsService;
        this.registeredClientRepository = registeredClientRepository;
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

        // Federated (external IDP) logins never go through MFA enrollment/challenge here — MFA
        // (TOTP) is a UIDAM-internal-login concept only. External IDPs are expected to enforce
        // their own MFA policy upstream, so we always pass federated users through regardless
        // of the tenant's MfaMode.
        if (auth instanceof OAuth2AuthenticationToken) {
            LOGGER.info("[MFA-FILTER] Federated (external IDP) login for user='{}' – MFA not applicable, "
                    + "passing through", username);
            chain.doFilter(request, response);
            return;
        }

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
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("[MFA-FILTER] client_id='{}' is in MFA skip-list for tenant='{}' – passing through",
                        InputSanitizer.forLog(clientId), InputSanitizer.forLog(tenant));
            }
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

        if (mode == MfaMode.CONDITIONAL && !requiresStepUp(request, auth, policy, clientId, accountName, tenant)) {
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
            MfaPolicyProperties policy, String clientId, String accountName, String tenant) {

        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("[MFA-FILTER] CONDITIONAL on client_id='{}'", InputSanitizer.forLog(clientId));
            LOGGER.info("[MFA-FILTER] CONDITIONAL on account_id='{}'", InputSanitizer.forLog(accountName));
        }
        // 0. Per-user MFA override: mfaRequired attribute from user-management (highest priority in CONDITIONAL)
        //    true  → always enforce MFA for this user
        //    false → always skip MFA for this user
        //    null  → no per-user override, continue to normal step-up rules
        Boolean perUserMfa = resolvePerUserMfaOverride(auth);
        if (perUserMfa != null) {
            LOGGER.info("[MFA-FILTER] CONDITIONAL per-user mfaRequired='{}' for user='{}' – overrides step-up",
                    perUserMfa, auth.getName());
            return perUserMfa;
        }

        // 1. Step-up client check: if the requesting client_id is in the step-up list → enforce MFA
        Set<String> stepUpClients = policy.getStepUpClientSet();
        if (!stepUpClients.isEmpty() && clientId != null && !clientId.isBlank()) {
            boolean clientMatch = stepUpClients.stream().anyMatch(c -> c.equalsIgnoreCase(clientId));
            LOGGER.info("[MFA-FILTER] CONDITIONAL step-up check on stepUpClients={} -> {}",
                stepUpClients, clientMatch);
            if (clientMatch) {
                return true;
            }
        }

        // 2. Step-up account check: if the user's account ID (from user-management record) is in the step-up list
        Set<String> stepUpAccounts = policy.getStepUpAccountSet();
        if (!stepUpAccounts.isEmpty() && accountName != null && !accountName.isBlank()) {
            boolean accountMatch = stepUpAccounts.stream().anyMatch(a -> a.equalsIgnoreCase(accountName));
            LOGGER.info("[MFA-FILTER] CONDITIONAL step-up check on stepUpAccounts={} -> {}",
                    stepUpAccounts, accountMatch);
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

        return matchesStepUpScopes(request, auth, stepUpScopes, tenant);
    }

    /**
     * Matches step-up scopes against the scopes the issued token will carry: the requested scopes
     * (always kept in the token), plus the user's scopes when the request is empty or will be expanded
     * as an OIDC-only request.
     */
    private boolean matchesStepUpScopes(HttpServletRequest request, Authentication auth,
            Set<String> stepUpScopes, String tenant) {
        Set<String> requestedScopes = extractRequestedScopes(request);
        if (requestedScopes.stream().anyMatch(stepUpScopes::contains)) {
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("[MFA-FILTER] CONDITIONAL step-up matched requested scopes={} vs stepUp={}",
                        requestedScopes.stream().map(InputSanitizer::forLog).collect(Collectors.toSet()),
                        stepUpScopes);
            }
            return true;
        }
        boolean expandedToUserScopes = CommonMethodsUtils.isOidcOnlyScopeRequest(requestedScopes)
                && isOidcOnlyScopeExpansionEnabled(tenant);
        if (!requestedScopes.isEmpty() && !expandedToUserScopes) {
            LOGGER.info("[MFA-FILTER] CONDITIONAL step-up: no requested scope matched stepUp={}", stepUpScopes);
            return false;
        }

        Set<String> userScopes = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(MfaChallengeFilter::normalizeScope)
                .collect(Collectors.toSet());
        if (expandedToUserScopes) {
            Optional<Set<String>> tokenEligible = resolveExpansionEligibleScopes(request.getParameter("client_id"));
            if (tokenEligible.isPresent()) {
                userScopes.retainAll(tokenEligible.get());
            }
        }
        boolean match = userScopes.stream().anyMatch(stepUpScopes::contains);
        LOGGER.info("[MFA-FILTER] CONDITIONAL step-up check on user scopes={} vs stepUp={} -> {}",
                userScopes, stepUpScopes, match);
        return match;
    }

    /**
     * Mirrors token issuance: an OIDC-only request expands only to the client's registered scopes, and not at
     * all for clients requiring consent. Returns empty when the client cannot be resolved, so the caller falls
     * back to checking every user scope (the stricter choice).
     */
    private Optional<Set<String>> resolveExpansionEligibleScopes(String clientId) {
        if (registeredClientRepository == null || clientId == null || clientId.isBlank()) {
            return Optional.empty();
        }
        try {
            RegisteredClient client = registeredClientRepository.findByClientId(clientId);
            if (client == null) {
                return Optional.empty();
            }
            return Optional.of(client.getClientSettings().isRequireAuthorizationConsent()
                    ? Set.of() : client.getScopes());
        } catch (Exception ex) {
            LOGGER.warn("[MFA-FILTER] Could not resolve client scopes for step-up check: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    private boolean isOidcOnlyScopeExpansionEnabled(String tenant) {
        try {
            TenantProperties props = tenantConfigurationService.getTenantProperties(tenant);
            return props != null && props.getClient() != null
                    && Boolean.TRUE.equals(props.getClient().getOidcOnlyScopeExpansionEnabled());
        } catch (Exception ex) {
            // Treat as expanded so MFA is evaluated against the broader user scopes
            LOGGER.warn("[MFA-FILTER] Could not resolve OIDC-only scope expansion for tenant='{}': {}",
                    tenant, ex.getMessage());
            return true;
        }
    }

    /**
     * Returns the per-user {@code mfaRequired} override from {@link CustomUserPwdAuthenticationToken},
     * or {@code false} if the token type does not carry a per-user override.
     */
    private Boolean resolvePerUserMfaOverride(Authentication auth) {
        if (auth instanceof CustomUserPwdAuthenticationToken customToken) {
            return customToken.getMfaRequired();
        }
        return Boolean.FALSE;
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
        try {
            metricsService.incrementMetricsForTenant(tenant, MetricType.MFA_ENROLLMENT_INITIATED);
        } catch (Exception ex) {
            LOGGER.error("[MFA-FILTER] Failed to record MFA_ENROLLMENT_INITIATED metric: {}", ex.getMessage(), ex);
        }
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
                || CLIENT_AUTHENTICATED_ENDPOINTS.stream().anyMatch(uri::contains);
    }

    // Token-authenticated endpoints: the caller is a client presenting credentials or a token,
    // not a user completing an interactive login, so MFA must never intercept them.
    private static final List<String> CLIENT_AUTHENTICATED_ENDPOINTS = List.of(
            "oauth2/token", "oauth2/revoke", "oauth2/introspect", "oauth2/device_authorization",
            "connect/register", "userinfo", "oauth2/jwks");
}
