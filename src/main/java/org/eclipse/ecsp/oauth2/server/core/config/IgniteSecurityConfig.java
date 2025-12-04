/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.config;

import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.authentication.filters.CustomUserPwdAuthenticationFilter;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.CustomAccessTokenFailureHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.CustomAuthCodeFailureHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.CustomAuthCodeSuccessHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.CustomRevocationSuccessHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.FederatedIdentityAuthenticationSuccessHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.providers.CustomUserPwdAuthenticationProvider;
import org.eclipse.ecsp.oauth2.server.core.authentication.validator.CustomScopeValidator;
import org.eclipse.ecsp.oauth2.server.core.filter.TenantAwareAuthenticationFilter;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRequestRepository;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationSecurityContextRepository;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseAuthorizationRequestRepository;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseAuthorizedClientService;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseSecurityContextRepository;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.util.SessionTenantResolver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.util.UriComponentsBuilder;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.COMMA_DELIMITER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.DEFAULT_LOGIN_MATCHER_PATTERN;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_FAILURE_HANDLER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_HANDLER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_MATCHER_PATTERN;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGOUT_MATCHER_PATTERN;
import static org.springframework.security.config.Customizer.withDefaults;

/**
 * This is the main configuration class for the Ignite Security module. It contains all the necessary beans and
 * configurations required for the security module. It includes configurations for OAuth2, form login, session
 * management, and more. It also includes the necessary beans for handling authentication and authorization.
 */
@Configuration 
@EnableWebSecurity 
@EnableMethodSecurity
public class IgniteSecurityConfig {

    // Security matcher patterns
    private static final String OAUTH2_PATTERN = "/oauth2/**";
    private static final String TENANT_OAUTH2_PATTERN = "/*/oauth2/**";
    private static final String WELL_KNOWN_OAUTH_SERVER = "/.well-known/oauth-authorization-server/";
    private static final String WELL_KNOWN_OAUTH_SERVER_TENANT = "/.well-known/oauth-authorization-server/*/";
    private static final String OAUTH2_CALLBACK_PATTERN = "/*/login/oauth2/code/**";
    private static final String OAUTH2_AUTHORIZATION_PATTERN = "/*/oauth2/authorization/**";
    private static final String OAUTH2_LOGOUT_ENDPOINT = "/oauth2/logout";
    private static final String POST_METHOD = "POST";

    @Value("${server.servlet.session.timeout}")
    private String sessionTimeout;

    @Value("${user.session.force.login}")
    private boolean forceLogin;

    @Value("${cors.allowed.origin.patterns}")
    private String corsAllowedOriginPatterns;

    @Value("${cors.allowed.methods}")
    private String corsAllowedMethods;

    @Value("${session.recreation.policy}")
    private String sessionRecreationPolicy;   
    
    private static final int INT_TWO = 2;

    private final TenantConfigurationService tenantConfigurationService;
    private final AuthorizationMetricsService authorizationMetricsService;
    private final AuditLogger auditLogger;

    /**
     * Constructor for the IgniteSecurityConfig class. It stores the TenantConfigurationService,
     * AuthorizationMetricsService, and AuditLogger for dynamic tenant property resolution,
     * metrics collection, and audit logging.
     *
     * @param tenantConfigurationService Service for managing tenant configurations.
     * @param authorizationMetricsService Service for collecting authorization metrics.
     * @param auditLogger Service for logging audit events.
     */
    public IgniteSecurityConfig(TenantConfigurationService tenantConfigurationService,
                               AuthorizationMetricsService authorizationMetricsService,
                               AuditLogger auditLogger) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.authorizationMetricsService = authorizationMetricsService;
        this.auditLogger = auditLogger;
    }

    /**
     * This method configures the security filter chain for the application. It sets up the request cache, session
     * management, security context repository, CORS configuration, and OAuth2 authorization server configuration.
     * It also handles login and logout configurations, authentication providers, and exception handling.
     *
     * @param http HttpSecurity object used for configuring web based security for specific http requests.
     * @param registeredClientRepository Repository for OAuth2 registered clients.
     * @param customAccessTokenFailureHandler Handler for access token failure responses.
     * @param customUserPwdAuthProvider Custom authentication provider for user/password authentication.
     * @param customAuthCodeFailureHandler Handler for authorization code failure responses.
     * @param authenticationConfiguration Authentication configuration for the application.
     * @param authorizationSecurityContextRepository Repository for authorization security context.
     * @param oauth2AuthorizationService Service for managing OAuth2 authorizations.
     * @param authorizationRequestRepository Repository for OAuth2 authorization requests.
     * @param clientRegistrationRepository Optional repository for client registrations.
     * @param customScopeValidator Custom scope validator for OAuth2 requests.
     * @param databaseSecurityContextRepository Database security context repository.
     * @param federatedIdentityAuthenticationSuccessHandler Handler for successful federated authentication.
     * @return Configured SecurityFilterChain instance.
     * @throws Exception If an error occurs during configuration.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
            RegisteredClientRepository registeredClientRepository,
            CustomAccessTokenFailureHandler customAccessTokenFailureHandler,
            CustomUserPwdAuthenticationProvider customUserPwdAuthProvider,
            CustomAuthCodeFailureHandler customAuthCodeFailureHandler,
            AuthenticationConfiguration authenticationConfiguration,
            AuthorizationSecurityContextRepository authorizationSecurityContextRepository,
            OAuth2AuthorizationService oauth2AuthorizationService,
            AuthorizationRequestRepository authorizationRequestRepository,
            Optional<ClientRegistrationRepository> clientRegistrationRepository,
            CustomScopeValidator customScopeValidator,
            DatabaseSecurityContextRepository databaseSecurityContextRepository,
            FederatedIdentityAuthenticationSuccessHandler 
            federatedIdentityAuthenticationSuccessHandler) throws Exception {

        RequestCache requestCache = new CookieRequestCache();
        http.requestCache(requestCacheConfigurer -> requestCacheConfigurer.requestCache(requestCache));
        SavedRequestAwareAuthenticationSuccessHandler savedRequestAwareAuthenticationSuccessHandler 
                = new SavedRequestAwareAuthenticationSuccessHandler();
        savedRequestAwareAuthenticationSuccessHandler.setRequestCache(requestCache);
        http.sessionManagement(session -> session.sessionCreationPolicy(
                SessionCreationPolicy.valueOf(sessionRecreationPolicy)));

        http.securityContext(securityContextConfigurer -> securityContextConfigurer
                .securityContextRepository(databaseSecurityContextRepository));
        handleLogin(http, authorizationRequestRepository, 
                clientRegistrationRepository, federatedIdentityAuthenticationSuccessHandler);

        // Use global session policy at startup (tenant-specific policies handled by filters)
        http.sessionManagement(session -> session.sessionCreationPolicy(
                SessionCreationPolicy.valueOf(sessionRecreationPolicy)));

        setSecurityMachers(http);
        
        http.cors(corsCustomizer -> corsCustomizer.configurationSource(request -> {
            CorsConfiguration corsConfiguration = new CorsConfiguration();
            corsConfiguration
                    .setAllowedOriginPatterns(Stream.of(corsAllowedOriginPatterns.split(COMMA_DELIMITER)).toList());
            corsConfiguration.setAllowedMethods(Stream.of(corsAllowedMethods.split(COMMA_DELIMITER)).toList());
            return corsConfiguration;
        })); 
        // For full per-request tenant awareness, would need to inject TenantConfigurationService
        CustomAuthCodeSuccessHandler customAuthCodeSuccessHandler = new CustomAuthCodeSuccessHandler(
                databaseSecurityContextRepository, forceLogin);
        http.with(new OAuth2AuthorizationServerConfigurer(), oauth2 -> oauth2
                .registeredClientRepository(registeredClientRepository)
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint.errorResponseHandler(customAccessTokenFailureHandler))
                .authorizationEndpoint(
                        authorizationEndpoint -> authorizationEndpoint.authenticationProvider(customUserPwdAuthProvider)
                                .authenticationProviders(configureAuthenticationValidator(customScopeValidator))
                                .authorizationResponseHandler(customAuthCodeSuccessHandler)
                                .errorResponseHandler(customAuthCodeFailureHandler)).oidc(Customizer.withDefaults())
                .clientAuthentication(clientAuthenticationConfigurer -> clientAuthenticationConfigurer
                        .errorResponseHandler(customAccessTokenFailureHandler))
                .tokenRevocationEndpoint(tokenRevocationEndpointConfigurer -> tokenRevocationEndpointConfigurer
                        .revocationResponseHandler(new CustomRevocationSuccessHandler(oauth2AuthorizationService,
                                databaseSecurityContextRepository))));

        http.exceptionHandling(c -> c.defaultAuthenticationEntryPointFor(
                customLoginAuthenticationEntryPoint(), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));
        CustomUserPwdAuthenticationFilter customUserPwdAuthenticationFilter = new CustomUserPwdAuthenticationFilter(
                authenticationConfiguration.getAuthenticationManager(), this.tenantConfigurationService,
                this.authorizationMetricsService, this.auditLogger);
        customUserPwdAuthenticationFilter.setSecurityContextRepository(databaseSecurityContextRepository);
        customUserPwdAuthenticationFilter
                .setAuthenticationSuccessHandler(savedRequestAwareAuthenticationSuccessHandler);
        customUserPwdAuthenticationFilter
                .setAuthenticationFailureHandler(customSimpleUrlAuthenticationFailureHandler());
        http.addFilterBefore(customUserPwdAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        // This filter ensures only tenant-allowed authentication methods are executed
        TenantAwareAuthenticationFilter tenantAwareAuthenticationFilter = new TenantAwareAuthenticationFilter(
                this.tenantConfigurationService);
        http.addFilterAfter(tenantAwareAuthenticationFilter,
                org.springframework.security.web.authentication.www.BasicAuthenticationFilter.class);
        
        return http.build();
    }

    /**
     * This method sets the security matchers for the HttpSecurity object. It configures the security matchers to
     * handle all OAuth2 patterns, including authorization server and external IDP.
     *
     * @param http HttpSecurity object used for configuring web based security for specific http requests.
     * @throws Exception May throw an exception if there's an error during the configuration.
     */
    @SuppressWarnings("java:S4502") // CSRF protection intentionally disabled for OAuth2 logout endpoints
    private void setSecurityMachers(HttpSecurity http) throws Exception {
        // Configure security matchers for ALL OAuth2 patterns (authorization server + external IDP)
        http.securityMatchers(matchers -> matchers.requestMatchers(
                DEFAULT_LOGIN_MATCHER_PATTERN,
                TENANT_OAUTH2_PATTERN, OAUTH2_PATTERN,
                WELL_KNOWN_OAUTH_SERVER, WELL_KNOWN_OAUTH_SERVER_TENANT,
                OAUTH2_CALLBACK_PATTERN, // Tenant-prefixed OAuth2 callback URLs
                LOGIN_MATCHER_PATTERN, 
                LOGOUT_MATCHER_PATTERN))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(DEFAULT_LOGIN_MATCHER_PATTERN, LOGIN_MATCHER_PATTERN).permitAll()
                        .requestMatchers(LOGOUT_MATCHER_PATTERN).permitAll()
                        .requestMatchers(OAUTH2_AUTHORIZATION_PATTERN, OAUTH2_CALLBACK_PATTERN)
                            .permitAll() // Tenant-prefixed
                        .requestMatchers(WELL_KNOWN_OAUTH_SERVER, WELL_KNOWN_OAUTH_SERVER_TENANT)
                            .permitAll() // Well-known endpoints (both root and tenant-prefixed)
                        .anyRequest()
                        .authenticated())
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        // SonarQube S4502: CSRF protection is intentionally disabled for OAuth2 logout endpoints
                        // to support OIDC RP-Initiated Logout specification compliance where external clients
                        // may not have access to CSRF tokens. Security is ensured through:
                        // 1. Client credential validation
                        // 2. ID token hint validation  
                        // 3. Redirect URI validation
                        // 4. State parameter validation
                        .ignoringRequestMatchers(request -> {
                            String requestUri = request.getRequestURI();
                            String method = request.getMethod();
                            // Only disable CSRF for POST requests to logout endpoints
                            // Using safe string operations instead of regex to prevent ReDoS vulnerability
                            return POST_METHOD.equals(method) 
                                   && (requestUri.endsWith(OAUTH2_LOGOUT_ENDPOINT) 
                                    || requestUri.contains(OAUTH2_LOGOUT_ENDPOINT + "/"));
                        }));
    }

    /**
     * This method handles the login configuration for the application. It sets up form-based login and OAuth2 login
     * based on the provided repositories.
     *
     * @param http HttpSecurity object used for configuring web based security for specific http requests.
     * @param authorizationRequestRepository Repository for OAuth2 authorization requests.
     * @param clientRegistrationRepository Optional repository for client registration information.
     * @param federatedIdentityAuthenticationSuccessHandler Handler for successful federated authentication.
     * @throws Exception May throw an exception if there's an error during the configuration.
     */
    private void handleLogin(HttpSecurity http, AuthorizationRequestRepository authorizationRequestRepository,
            Optional<ClientRegistrationRepository> clientRegistrationRepository,
            FederatedIdentityAuthenticationSuccessHandler 
            federatedIdentityAuthenticationSuccessHandler) throws Exception {
        // Runtime tenant-aware filters will determine which to use per request
        // Always configure form login (tenant-aware filter will control access)
        enableFormLogin(http);
        
        // Always configure OAuth login if repository is available (tenant-aware filter will control access)
        enableOauthLogin(http, authorizationRequestRepository, 
                clientRegistrationRepository, federatedIdentityAuthenticationSuccessHandler);
    }

    /**
     * This method creates an instance of DatabaseSecurityContextRepository.
     * Uses tenant-aware session timeout configuration.
     *
     * @param authorizationSecurityContextRepository AuthorizationSecurityContextRepository
     * @return DatabaseSecurityContextRepository
     */
    @Bean
    public DatabaseSecurityContextRepository createDatabaseSecurityContextRepository(
            AuthorizationSecurityContextRepository authorizationSecurityContextRepository) {
        return new DatabaseSecurityContextRepository(authorizationSecurityContextRepository,
                this.tenantConfigurationService, getTenantSessionTimeout());
    }

    /**
     * This method enables form-based login within the application. It configures the HttpSecurity object to allow form
     * login.
     *
     * @param http HttpSecurity object used for configuring web based security for specific http requests.
     * @throws Exception May throw an exception if there's an error during the configuration.
     */
    private void enableFormLogin(HttpSecurity http) throws Exception {
        http.formLogin(form -> form.loginPage(LOGIN_HANDLER));
    }

    /**
     * This method enables OAuth-based login within the application. It configures the HttpSecurity object for OAuth
     * login.
     *
     * @param http HttpSecurity object used for configuring web based security for specific http requests.
     * @param authorizationRequestRepository Repository for OAuth2 authorization requests.
     * @param clientRegistrationRepository Repository for client registration information.
     * @param federatedIdentityAuthenticationSuccessHandler Handler for successful federated authentication.
     * @throws Exception May throw an exception if there's an error during the configuration.
     */
    private void enableOauthLogin(HttpSecurity http, AuthorizationRequestRepository authorizationRequestRepository,
            Optional<ClientRegistrationRepository> clientRegistrationRepository,
            FederatedIdentityAuthenticationSuccessHandler federatedIdentityAuthenticationSuccessHandler)
            throws Exception {
        if (clientRegistrationRepository.isPresent()) {
            http.oauth2Login(
                    oauth2Login -> oauth2Login.clientRegistrationRepository(clientRegistrationRepository.get())
                            .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                                    .baseUri("/{tenantId}/oauth2/authorization") // Support tenant-prefixed URLs
                                    .authorizationRequestRepository(new DatabaseAuthorizationRequestRepository(
                                            authorizationRequestRepository, clientRegistrationRepository.get())))
                            .redirectionEndpoint(redirectionEndpoint -> redirectionEndpoint
                                    .baseUri("/{tenantId}/login/oauth2/code/*")) // Support tenant-prefixed callback
                            .authorizedClientService(new DatabaseAuthorizedClientService()).loginPage(LOGIN_HANDLER)
                            .successHandler(federatedIdentityAuthenticationSuccessHandler) // Use injected tenant-aware
                            .failureHandler((request, response, exception) -> {
                                String tenantId = SessionTenantResolver.getCurrentTenant();
                                String redirectUrl = tenantId != null ? "/" + tenantId + "/login?error=oauth2"
                                        : "/login?error=oauth2";
                                response.sendRedirect(redirectUrl);
                            })); // Add tenant-aware failure handler
        }
    }

    /**
     * This method configures the authentication validator for OAuth2 Authorization Code Request. It overrides the
     * default scope validator with a custom one.
     *
     * @return A Consumer functional interface that accepts a list of AuthenticationProvider.
     */
    private Consumer<List<AuthenticationProvider>> configureAuthenticationValidator(
            CustomScopeValidator customScopeValidator) {
        return authenticationProviders -> authenticationProviders.forEach(authenticationProvider -> {
            if (authenticationProvider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider 
                    oauth2AuthorizationCodeRequestAuthenticationProvider) {
                Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator =
                        // Reuse default redirect_uri validator
                        OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                                // Override default scope validator
                                .andThen(customScopeValidator);
                oauth2AuthorizationCodeRequestAuthenticationProvider
                        .setAuthenticationValidator(authenticationValidator);
            }
        });
    }

    /**
     * This method creates an instance of SessionRegistry which is used to manage sessions. The SessionRegistry keeps
     * track of all sessions in the application.
     *
     * @return A SessionRegistry object that can be used to retrieve sessions.
     */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /**
     * This method creates an instance of HttpSessionEventPublisher. The HttpSessionEventPublisher is a Spring Framework
     * class that publishes HttpSession-related events. It is typically used in combination with a SessionRegistry for
     * session management.
     *
     * @return A HttpSessionEventPublisher object that can be used to publish session events.
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
    

    /**
     * This method creates an instance of AuthenticationEntryPoint. custom authentication entrypoint 
     * to add request parameters and tenant specific issuer prefix.
     *
     * @return A AuthenticationEntryPoint object that can be generate login URL.
     */
    @Bean
    public AuthenticationEntryPoint customLoginAuthenticationEntryPoint() {
        return (request, response, authException) -> {
            // Extract all query parameters from the original request
            Map<String, String> params = new LinkedHashMap<>();
            Enumeration<String> paramNames = request.getParameterNames();
            while (paramNames.hasMoreElements()) {
                String name = paramNames.nextElement();
                params.put(name, request.getParameter(name));
            }
            // Extract issuer/tenant prefix from request URI
            String requestUri = request.getRequestURI();
            String issuerPrefix = "";
            // Example: /tenant1/oauth2/authorize
            if (requestUri.startsWith("/")) {
                String[] parts = requestUri.split("/");
                if (parts.length > INT_TWO && !"oauth2".equals(parts[1])) {
                    issuerPrefix = "/" + parts[1];
                }
            }
            UriComponentsBuilder builder = UriComponentsBuilder.fromPath(issuerPrefix + "/login");
            params.forEach(builder::queryParam);
            // Optionally, add issuerPrefix as a parameter
            if (!issuerPrefix.isEmpty()) {
                builder.queryParam("issuer", issuerPrefix.substring(1));
            }
            String redirectUrl = builder.build().toUriString();
            response.sendRedirect(redirectUrl);
        };
    }
    
    /**
     * Performs the redirect or forward to the {@code defaultFailureUrl} if set, otherwise
     * returns a 401 error code.
     * If redirecting or forwarding, {@code saveException} will be called to cache the
     * exception for use in the target view.
     */
    @Bean
    public AuthenticationFailureHandler customSimpleUrlAuthenticationFailureHandler() {
        return (request, response, exception) -> {
            
            HttpSession session = request.getSession(false);
            if (session != null) {
                request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
            }
            
            String errorUrl = "/" + request.getParameter("issuer") + LOGIN_FAILURE_HANDLER
                    + "&response_type=" + request.getParameter("response_type")
                    + "&client_id=" + request.getParameter("client_id")
                    + "&scope=" + request.getParameter("scope")
                    + "&redirect_uri=" + request.getParameter("redirect_uri")
                    + "&issuer=" + request.getParameter("issuer");
            response.sendRedirect(errorUrl);
        };
        
    }

    /**
     * Get tenant-specific session timeout, falling back to global configuration.
     * This method attempts to resolve tenant-specific session timeout but falls back to global setting.
     *
     * @return the session timeout to use
     */
    private String getTenantSessionTimeout() {
        // For now, return global setting as TenantProperties doesn't have sessionTimeout field
        // This can be enhanced when tenant-specific session timeout settings are added to TenantProperties
        return sessionTimeout;
    }

    /**
     * Creates a bean for FederatedIdentityAuthenticationSuccessHandler to handle successful OAuth2 authentication
     * with tenant-aware redirection.
     *
     * @return FederatedIdentityAuthenticationSuccessHandler instance
     */
    @Bean
    public FederatedIdentityAuthenticationSuccessHandler federatedIdentityAuthenticationSuccessHandler() {
        return new FederatedIdentityAuthenticationSuccessHandler();
    }

}
