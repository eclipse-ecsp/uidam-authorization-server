/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p>Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.authentication.handlers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.audit.context.HttpRequestContext;
import org.eclipse.ecsp.oauth2.server.core.audit.context.UserActorContext;
import org.eclipse.ecsp.oauth2.server.core.audit.enums.AuditEventType;
import org.eclipse.ecsp.oauth2.server.core.service.AuthorizationService;
import org.eclipse.ecsp.oauth2.server.core.service.ClientRegistrationManager;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseSecurityContextRepository;
import org.eclipse.ecsp.oauth2.server.core.util.SessionTenantResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The LogoutHandler class handles successful logout events for OpenID Connect RP-Initiated Logout. This class
 * implements the logout flow according to the OIDC specification and handles token revocation, session invalidation,
 * and post-logout redirects.
 */
@Component
public class LogoutHandler {

    private static final String OAUTH2_LOGOUT_SUCCESS = "/%s/oauth2/logout/success";

    private static final String OAUTH2_LOGOUT_ERROR_ERROR = "/%s/oauth2/logout/error?error=%s";

    private static final int INTEGER_SEVEN = 7;

    private static final Logger LOGGER = LoggerFactory.getLogger(LogoutHandler.class);
    private static final String COMPONENT_NAME = "UIDAM_AUTHORIZATION_SERVER";

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private final AuthorizationService authorizationService;
    private final ClientRegistrationManager registeredClientManger;
    private final DatabaseSecurityContextRepository databaseSecurityContextRepository;
    private final AuditLogger auditLogger;
    
    private final Set<String> whitelistedCustomHosts;

    /**
     * Constructor for dependency injection using Spring's constructor injection.
     */
    public LogoutHandler(AuthorizationService authorizationService, ClientRegistrationManager registeredClientManger,
            DatabaseSecurityContextRepository databaseSecurityContextRepository,
            AuditLogger auditLogger,
            @Value("${logout.redirect.whitelisted.custom.hosts:localhost,127.0.0.1}") String allowedHosts) {
        this.authorizationService = authorizationService;
        this.registeredClientManger = registeredClientManger;
        this.databaseSecurityContextRepository = databaseSecurityContextRepository;
        this.auditLogger = auditLogger;
        this.whitelistedCustomHosts = Arrays.stream(allowedHosts.split(",")).map(String::trim)
                .collect(Collectors.toSet());
    }

    /**
     * Handles the logout success processing according to OpenID Connect RP-Initiated Logout specification.
     *
     * @param request HTTP servlet request
     * @param response HTTP servlet response
     * @param authentication Current authentication context
     * @param idTokenHint ID token hint (access token in UIDAM's case)
     * @param clientId Client ID that initiated the logout
     * @param postLogoutRedirectUri URI to redirect after logout
     * @param state State parameter to maintain between request and callback
     * @throws IOException if an I/O error occurs during processing
     */
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication,
            String idTokenHint, String clientId, String postLogoutRedirectUri, String state) throws IOException {

        LOGGER.info("Processing OIDC logout - clientId: {}, postLogoutRedirectUri: {}", clientId,
                postLogoutRedirectUri);

        String sessionId = request.getSession(false) != null ? request.getSession().getId() : null;

        // 1. Validate post_logout_redirect_uri against registered client
        String validatedRedirectUri = validatePostLogoutRedirectUri(clientId, postLogoutRedirectUri);

        OAuth2Authorization authorization = null;
        try {
            // 2. Validate and extract information from id_token_hint (access token)
            if (StringUtils.hasText(idTokenHint)) {
                authorization = revokeTokens(idTokenHint, clientId);
            }

            // 3. Invalidate session and security context
            invalidateSession(request, sessionId);
            
            // Log successful logout audit event
            logLogoutSuccess(request, authentication, authorization);
            
            // 4. Perform redirect based on scenario
            performLogoutRedirect(request, response, validatedRedirectUri, state, null);

        } catch (OAuth2AuthenticationException e) {
            LOGGER.error("OAuth2 error during OIDC logout processing: {}", e.getError().getDescription(), e);
            handleLogoutError(request, response, validatedRedirectUri, state, e.getError());
        } catch (Exception e) {
            LOGGER.error("Unexpected error during OIDC logout processing", e);
            OAuth2Error error = new OAuth2Error("server_error", "An unexpected error occurred during logout", null);
            handleLogoutError(request, response, validatedRedirectUri, state, error);
        }
    }

    /**
     * Revokes all tokens associated with the given access token.
     *
     * @param accessToken Access token to revoke
     * @param clientId Client ID associated with the token
     * @return OAuth2Authorization containing token claims (userId, accountId) for audit logging
     */
    private OAuth2Authorization revokeTokens(String accessToken, String clientId) {
        String token = accessToken.startsWith("Bearer ") ? accessToken.substring(INTEGER_SEVEN) : accessToken;

        // Find authorization by access token
        OAuth2Authorization authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        
        if (authorization == null) {
            throwError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint");
        }
        
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorization.getAuthorizationGrantType())) {
            throwError(OAuth2ErrorCodes.INVALID_GRANT, OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace("Retrieved authorization with ID Token");
        }
        LOGGER.info("Revoking tokens for authorization: {}", authorization.getId());
        // Check if the access token is valid
        OAuth2Authorization.Token<OAuth2AccessToken> dbAccessToken = authorization.getAccessToken();
        if (dbAccessToken.isInvalidated() || dbAccessToken.isExpired()) {
            // Expired ID Token should be accepted
            throwError(OAuth2ErrorCodes.INVALID_TOKEN, "id_token_hint");
        }

        String registredClient = authorization.getRegisteredClientId();

        if (StringUtils.hasText(clientId) && !registredClient.equals(clientId)) {
            throwError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_ID);
        }
        // Revoke access token
        if (authorization.getAccessToken() != null) {
            authorizationService.revokenTokenByPrincipalAndClientId(authorization.getPrincipalName(), clientId);
            LOGGER.debug("Access token revoked for client: {}", clientId);
        }
        
        return authorization;

    }

    /**
     * Validates the post_logout_redirect_uri against the registered client's allowed URIs.
     *
     * @param clientId Client ID to validate against
     * @param postLogoutRedirectUri URI to validate
     * @return Validated redirect URI or null if validation fails
     */
    private String validatePostLogoutRedirectUri(String clientId, String postLogoutRedirectUri) {
        if (!StringUtils.hasText(postLogoutRedirectUri) || !StringUtils.hasText(clientId)) {
            LOGGER.warn("Post logout redirect URI or client ID is empty");
            return null;
        }
        try {
            RegisteredClient registeredClient = registeredClientManger.findByClientId(clientId);
            if (registeredClient == null) {
                LOGGER.warn("Client not found: {}", clientId);
                throwError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_ID);
            }
            // Validate URI against registered post logout redirect URIs
            if (registeredClient.getPostLogoutRedirectUris().contains(postLogoutRedirectUri)) {
                LOGGER.debug("Post logout redirect URI validated successfully: {}", postLogoutRedirectUri);
                return postLogoutRedirectUri;
            } else if (!registeredClient.getPostLogoutRedirectUris().isEmpty()) {
                LOGGER.warn("Post logout redirect URI not allowed for client {}: {}", clientId, postLogoutRedirectUri);
                throwError(OAuth2ErrorCodes.INVALID_REDIRECT_URI, OAuth2ParameterNames.REDIRECT_URI);
            } else {
                LOGGER.warn("Post logout redirect URI not registered for client {}: {}", clientId,
                        postLogoutRedirectUri);
                return null;
            }
        } catch (Exception e) {
            LOGGER.error("Error validating post logout redirect URI", e);
            return null;
        }
        return postLogoutRedirectUri;
    }

    /**
     * Invalidates the current session and updates security context in database.
     *
     * @param request HTTP servlet request
     * @param sessionId Session ID to invalidate
     */
    private void invalidateSession(HttpServletRequest request, String sessionId) {
        try {
            // Invalidate HTTP session
            if (request.getSession(false) != null) {
                request.getSession().invalidate();
                LOGGER.debug("HTTP session invalidated");
            }
            // Update security context in database to unauthenticated
            if (StringUtils.hasText(sessionId)) {
                databaseSecurityContextRepository.unauthenticatedContextInDb(sessionId);
                LOGGER.debug("Security context updated to unauthenticated for session: {}", sessionId);
            }
        } catch (Exception e) {
            LOGGER.error("Error invalidating session", e);
        }
    }

    /**
     * Performs the logout redirect based on validated parameters.
     * SonarQube S5146: Redirect URI is validated against registered URIs and checked for security.
     * Suppress this warning as the redirect is not open to forging attacks.
     *
     * @param request HTTP servlet request
     * @param response HTTP servlet response
     * @param postLogoutRedirectUri Validated post logout redirect URI
     * @param state State parameter to include in redirect
     * @param error OAuth2Error if an error occurred, null for success
     * @throws IOException if an I/O error occurs during redirect
     */
    @SuppressWarnings("java:S5146")
    private void performLogoutRedirect(HttpServletRequest request, HttpServletResponse response,
            String postLogoutRedirectUri, String state, OAuth2Error error) throws IOException {
        String redirectUri;
        if (StringUtils.hasText(postLogoutRedirectUri)) {
            // Build redirect URI with state parameter and error if provided
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(postLogoutRedirectUri);
            if (StringUtils.hasText(state)) {
                uriBuilder.queryParam("state", state);
            }
            if (error != null) {
                uriBuilder.queryParam("error", error.getErrorCode());
                if (StringUtils.hasText(error.getDescription())) {
                    // Manually encode the error description to avoid illegal character issues
                    String encodedDescription = URLEncoder.encode(error.getDescription(), StandardCharsets.UTF_8);
                    uriBuilder.queryParam("error_description", encodedDescription);
                }
            }
            redirectUri = uriBuilder.build().toUriString();
            LOGGER.info("Redirecting to post logout redirect URI: {}", redirectUri);
        } else {
            // No redirect URL configured - redirect to internal pages
            if (error != null) {
                redirectUri = String.format(OAUTH2_LOGOUT_ERROR_ERROR, SessionTenantResolver.getCurrentTenant(),
                        error.getErrorCode());
                LOGGER.info("Redirecting to logout error page: {}", redirectUri);
            } else {
                redirectUri = String.format(OAUTH2_LOGOUT_SUCCESS, SessionTenantResolver.getCurrentTenant());
                LOGGER.info("Redirecting to logout success page: {}", redirectUri);
            }
        }

        // Perform secure redirect
        // SonarQube S5146: Redirect URI is validated against registered URIs and checked for security.
        if (isSecureRedirectUri(redirectUri)) {
            redirectStrategy.sendRedirect(request, response, redirectUri);
        } else {
            LOGGER.warn("Insecure redirect URI blocked: {}", redirectUri);
            response.sendRedirect(String.format(OAUTH2_LOGOUT_ERROR_ERROR, "server_error"));
        }
    } 
    
    /**
     * Simple validation to check if redirect URI is secure. This is a basic implementation - you may want to enhance
     * this based on your security requirements.
     *
     * @param redirectUri URI to validate
     * @return true if URI is considered secure
     */
    private boolean isSecureRedirectUri(String redirectUri) {
        if (!StringUtils.hasText(redirectUri)) {
            return false;
        }
        try {
            URI uri = URI.create(redirectUri);
            // Allow HTTPS, relative paths, and whitelisted custom hosts for HTTP
            return redirectUri.startsWith("https://") || redirectUri.startsWith("/")
                    || (redirectUri.startsWith("http://") && uri.getHost() != null
                            && whitelistedCustomHosts.contains(uri.getHost()));
        } catch (Exception e) {
            LOGGER.warn("Invalid redirect URI format: {}", redirectUri);
            return false;
        }
    }

    /**
     * Handles errors that occur during logout processing.
     *
     * @param request HTTP servlet request
     * @param response HTTP servlet response
     * @param postLogoutRedirectUri Post logout redirect URI if available
     * @param state State parameter if available
     * @param error OAuth2Error that occurred
     * @throws IOException if an I/O error occurs during error handling
     */
    private void handleLogoutError(HttpServletRequest request, HttpServletResponse response,
            String postLogoutRedirectUri, String state, OAuth2Error error) throws IOException {
        LOGGER.error("Logout error occurred: {} - {}", error.getErrorCode(), error.getDescription());

        // Validate redirect URI for error handling
        String validatedRedirectUri = null;
        // We need clientId to validate, but for error cases we'll be more permissive
        // and check if the URI looks reasonable
        if (StringUtils.hasText(postLogoutRedirectUri) && isSecureRedirectUri(postLogoutRedirectUri)) {
            validatedRedirectUri = postLogoutRedirectUri;
        }

        // Perform error redirect
        performLogoutRedirect(request, response, validatedRedirectUri, state, error);
    }

    private static void throwError(String errorCode, String parameterName) {
        OAuth2Error error = new OAuth2Error(errorCode, "Error with Logout Request Parameter: " + parameterName, null);
        throw new OAuth2AuthenticationException(error);
    }
    
    /**
     * Logs successful logout audit event.
     *
     * @param request HTTP servlet request
     * @param authentication Current authentication context (may be null if already invalidated)
     * @param authorization OAuth2Authorization containing access token with user claims (userId, accountId)
     */
    private void logLogoutSuccess(HttpServletRequest request, Authentication authentication, 
                                  OAuth2Authorization authorization) {
        try {
            // Extract username from authentication
            String username = authentication != null ? authentication.getName() : "unknown";
            
            // Extract userId and accountId from access token claims if available
            String userId = null;
            String accountId = null;
            String accountName = null;
            
            if (authorization != null && authorization.getAccessToken() != null) {
                OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
                if (accessToken.getClaims() != null) {
                    Object userIdClaim = accessToken.getClaims().get("user_id");
                    Object accountIdClaim = accessToken.getClaims().get("accountId");
                    Object accountNameClaim = accessToken.getClaims().get("accountName");
                    
                    userId = userIdClaim != null ? userIdClaim.toString() : null;
                    accountId = accountIdClaim != null ? accountIdClaim.toString() : null;
                    accountName = accountNameClaim != null ? accountNameClaim.toString() : null;
                }
            }
            
            UserActorContext actorContext = UserActorContext.builder()
                .userId(userId)
                .username(username)
                .accountId(accountId)
                .accountName(accountName)
                .build();
            
            HttpRequestContext requestContext = HttpRequestContext.from(request);
            
            String message = "User logged out successfully";
            
            auditLogger.log(
                AuditEventType.LOGOUT.getType(),
                COMPONENT_NAME,
                AuditEventResult.SUCCESS,
                message,
                actorContext,
                requestContext
            );
            
            LOGGER.debug("Audit log created for LOGOUT: userId={}, username={}", userId, username);
        } catch (Exception e) {
            LOGGER.error("Failed to create audit log for LOGOUT: {}", e.getMessage(), e);
        }
    }
}
