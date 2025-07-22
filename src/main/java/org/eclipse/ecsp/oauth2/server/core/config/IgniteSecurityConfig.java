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

import org.eclipse.ecsp.oauth2.server.core.authentication.filters.CustomUserPwdAuthenticationFilter;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.CustomAccessTokenFailureHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.CustomAuthCodeFailureHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.CustomAuthCodeSuccessHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.CustomRevocationSuccessHandler;
import org.eclipse.ecsp.oauth2.server.core.authentication.providers.CustomUserPwdAuthenticationProvider;
import org.eclipse.ecsp.oauth2.server.core.authentication.validator.CustomScopeValidator;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRequestRepository;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationSecurityContextRepository;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseAuthorizationRequestRepository;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseAuthorizedClientService;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseSecurityContextRepository;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.ECSP;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.COMMA_DELIMITER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_FAILURE_HANDLER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_HANDLER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_MATCHER_PATTERN;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGOUT_MATCHER_PATTERN;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.REQUEST_MATCHER_PATTERN;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

/**
 * This is the main configuration class for the Ignite Security module. It contains all the necessary beans and
 * configurations required for the security module. It includes configurations for OAuth2, form login, session
 * management, and more. It also includes the necessary beans for handling authentication and authorization.
 */
@Configuration 
@EnableWebSecurity 
@EnableMethodSecurity
public class IgniteSecurityConfig {

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
    
    private TenantProperties tenantProperties;

    /**
     * Constructor for the IgniteSecurityConfig class. It initializes the tenant properties using the provided
     * TenantConfigurationService.
     *
     * @param tenantConfigurationService Service for managing tenant configurations.
     */
    public IgniteSecurityConfig(TenantConfigurationService tenantConfigurationService) {
        tenantProperties = tenantConfigurationService.getTenantProperties(ECSP);
    }

    /**
     * This method creates an instance of SecurityFilterChain which is used to apply security configurations to the
     * application. The SecurityFilterChain is responsible for handling all security (Authentication and Authorization)
     * aspects of HTTP requests.
     *
     * @param http HttpSecurity Object for configuring web based security for specific http requests.
     * @param registeredClientRepository A repository for OAuth 2.0 RegisteredClient(s).
     * @param customAccessTokenFailureHandler Access Token Failure Handlers
     * @param customUserPwdAuthProvider User Pwd authentication provider
     * @param customAuthCodeFailureHandler Auth Code Failure Handler
     * @param tenantConfigurationService Tenant configuration Service
     * @param authenticationConfiguration Exports the authentication Configuration
     * @param authorizationSecurityContextRepository Security Context Repository
     * @param oauth2AuthorizationService Ignite Authorization Service
     * @param authorizationRequestRepository Authorization Request Repository
     * @param clientRegistrationRepository Client Registration Repository
     * @param customScopeValidator Custom Scope Validator
     * @return Security Filter Chain with respect to applied Spring Security
     * @throws Exception May throw exception or subclass of exception
     */
    @Bean 
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
            RegisteredClientRepository registeredClientRepository,
            CustomAccessTokenFailureHandler customAccessTokenFailureHandler,
            CustomUserPwdAuthenticationProvider customUserPwdAuthProvider,
            CustomAuthCodeFailureHandler customAuthCodeFailureHandler,
            TenantConfigurationService tenantConfigurationService,
            AuthenticationConfiguration authenticationConfiguration,
            AuthorizationSecurityContextRepository authorizationSecurityContextRepository,
            OAuth2AuthorizationService oauth2AuthorizationService,
            AuthorizationRequestRepository authorizationRequestRepository,
            Optional<ClientRegistrationRepository> clientRegistrationRepository,
            CustomScopeValidator customScopeValidator,
            DatabaseSecurityContextRepository databaseSecurityContextRepository) throws Exception {

        RequestCache requestCache = new CookieRequestCache();
        http.requestCache(requestCacheConfigurer -> requestCacheConfigurer.requestCache(requestCache));
        SavedRequestAwareAuthenticationSuccessHandler savedRequestAwareAuthenticationSuccessHandler 
                = new SavedRequestAwareAuthenticationSuccessHandler();
        savedRequestAwareAuthenticationSuccessHandler.setRequestCache(requestCache);
        http.sessionManagement(session -> session.sessionCreationPolicy(
                SessionCreationPolicy.valueOf(sessionRecreationPolicy)));

        http.securityContext(securityContextConfigurer -> securityContextConfigurer
                .securityContextRepository(databaseSecurityContextRepository));
        

        
        // Configure login methods BEFORE authorization rules
        if (tenantProperties.isExternalIdpEnabled()) {
            enableOauthLogin(http, authorizationRequestRepository, clientRegistrationRepository);
        }
        if (!tenantProperties.isExternalIdpEnabled() || tenantProperties.isInternalLoginEnabled()) {
            enableFormLogin(http);
        }

        // Configure security matchers and authorization rules
        http.securityMatchers(matchers -> matchers.requestMatchers(antMatcher(REQUEST_MATCHER_PATTERN),
                antMatcher(LOGIN_MATCHER_PATTERN), antMatcher(LOGOUT_MATCHER_PATTERN)))
                .authorizeHttpRequests(authorize -> authorize.requestMatchers(antMatcher(LOGIN_MATCHER_PATTERN))
                        .permitAll().requestMatchers(antMatcher(LOGOUT_MATCHER_PATTERN)).permitAll().anyRequest()
                        .authenticated())
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers(antMatcher(LOGOUT_MATCHER_PATTERN)));
        http.cors(corsCustomizer -> corsCustomizer.configurationSource(request -> {
            CorsConfiguration corsConfiguration = new CorsConfiguration();
            corsConfiguration
                    .setAllowedOriginPatterns(Stream.of(corsAllowedOriginPatterns.split(COMMA_DELIMITER)).toList());
            corsConfiguration.setAllowedMethods(Stream.of(corsAllowedMethods.split(COMMA_DELIMITER)).toList());
            return corsConfiguration;
        })); 
        // Apply OAuth2 Authorization Server configuration
        CustomAuthCodeSuccessHandler customAuthCodeSuccessHandler = new CustomAuthCodeSuccessHandler(
                databaseSecurityContextRepository, forceLogin);
        http.with(new OAuth2AuthorizationServerConfigurer(), oauth2 -> oauth2
                .registeredClientRepository(registeredClientRepository)
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint.errorResponseHandler(customAccessTokenFailureHandler))
                .authorizationEndpoint(
                        authorizationEndpoint -> authorizationEndpoint.authenticationProvider(customUserPwdAuthProvider)
                                .authenticationProviders(configureAuthenticationValidator(customScopeValidator))
                                .authorizationResponseHandler(customAuthCodeSuccessHandler)
                                .errorResponseHandler(customAuthCodeFailureHandler))
                .oidc(Customizer.withDefaults())
                .clientAuthentication(clientAuthenticationConfigurer -> clientAuthenticationConfigurer
                        .errorResponseHandler(customAccessTokenFailureHandler))
                .tokenRevocationEndpoint(tokenRevocationEndpointConfigurer -> tokenRevocationEndpointConfigurer
                        .revocationResponseHandler(new CustomRevocationSuccessHandler(oauth2AuthorizationService,
                                databaseSecurityContextRepository))));

        http.exceptionHandling(c -> c.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint(LOGIN_HANDLER), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));
        CustomUserPwdAuthenticationFilter customUserPwdAuthenticationFilter = new CustomUserPwdAuthenticationFilter(
                authenticationConfiguration.getAuthenticationManager(), tenantConfigurationService);
        customUserPwdAuthenticationFilter.setSecurityContextRepository(databaseSecurityContextRepository);
        customUserPwdAuthenticationFilter
                .setAuthenticationSuccessHandler(savedRequestAwareAuthenticationSuccessHandler);
        customUserPwdAuthenticationFilter
                .setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler(LOGIN_FAILURE_HANDLER));
        http.addFilterBefore(customUserPwdAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * This method creates an instance of DatabaseSecurityContextRepository.
     *
     * @param tenantConfigurationService TenantConfigurationService
     * @param authorizationSecurityContextRepository AuthorizationSecurityContextRepository
     * @return DatabaseSecurityContextRepository
     */
    @Bean
    public DatabaseSecurityContextRepository createDatabaseSecurityContextRepository(
            TenantConfigurationService tenantConfigurationService,
            AuthorizationSecurityContextRepository authorizationSecurityContextRepository) {
        return new DatabaseSecurityContextRepository(authorizationSecurityContextRepository, tenantConfigurationService,
                sessionTimeout);
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
     * @throws Exception May throw an exception if there's an error during the configuration.
     */
    private void enableOauthLogin(HttpSecurity http, AuthorizationRequestRepository authorizationRequestRepository,
            Optional<ClientRegistrationRepository> clientRegistrationRepository) throws Exception {
        if (clientRegistrationRepository.isPresent()) {
            http.oauth2Login(oauth2Login -> oauth2Login
                    .authorizationEndpoint(
                            authorizationEndpoint -> authorizationEndpoint.authorizationRequestRepository(
                                    new DatabaseAuthorizationRequestRepository(authorizationRequestRepository,
                                            clientRegistrationRepository.get())))
                    .authorizedClientService(new DatabaseAuthorizedClientService()).loginPage(LOGIN_HANDLER));
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

}