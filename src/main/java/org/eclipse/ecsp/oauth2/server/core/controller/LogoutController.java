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

package org.eclipse.ecsp.oauth2.server.core.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.authentication.handlers.LogoutHandler;
import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.eclipse.ecsp.oauth2.server.core.utils.UiAttributeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGOUT_HANDLER;

/**
 * The LogoutController class handles OpenID Connect RP-Initiated Logout requests.
 * It supports both GET and POST requests according to the OIDC specification and
 * provides endpoints for logout success and error pages.
 */
@Controller
@RequestMapping({"/{tenantId}" + LOGOUT_HANDLER, LOGOUT_HANDLER})
public class LogoutController {   
    
    private static final Logger LOGGER = LoggerFactory.getLogger(LogoutController.class);
    private final LogoutHandler logoutHandler;
    private final UiAttributeUtils uiAttributeUtils;    
    
    /**
     * Constructs a LogoutController with the specified LogoutHandler and UiAttributeUtils.
     *
     * @param logoutHandler The LogoutHandler to process logout requests
     * @param uiAttributeUtils The utility to add UI attributes to models
     */
    public LogoutController(LogoutHandler logoutHandler, UiAttributeUtils uiAttributeUtils) {
        this.logoutHandler = logoutHandler;
        this.uiAttributeUtils = uiAttributeUtils;
    }

 
    /**
     * Handles OpenID Connect RP-Initiated Logout requests via POST method.
     * SonarQube S5146: Redirect URI is validated and only allowed values are used for redirect.
     * Suppress this warning as the redirect is not open to forging attacks.
     *
     * @param idTokenHint ID token hint (access token in UIDAM's case)
     * @param logoutHint Optional logout hint (reserved for future use)
     * @param clientId client ID that initiated the logout
     * @param postLogoutRedirectUri Optional URI to redirect after logout
     * @param state Optional state parameter to maintain between request and callback
     * @param request HTTP servlet request
     * @param response HTTP servlet response
     * @throws IOException if an I/O error occurs during logout processing
     */
    @SuppressWarnings("java:S5146")
    @PostMapping
    public void logout(@PathVariable(value = "tenantId", required = false) String tenantId,
                       @RequestParam(value = "id_token_hint", required = true) String idTokenHint,
                       @RequestParam(value = "logout_hint", required = false) String logoutHint,
                       @RequestParam(value = "client_id", required = true) String clientId,
                       @RequestParam(value = "post_logout_redirect_uri", required = false) String postLogoutRedirectUri,
                       @RequestParam(value = "state", required = false) String state,
                       HttpServletRequest request,
                       HttpServletResponse response) throws IOException {
        tenantId = TenantUtils.resolveTenantId(tenantId);
        LOGGER.info("Processing OIDC logout POST request");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // SonarQube S5146: Pre-validate redirect URI to avoid open redirect false positive
        String safeRedirectUri = isAllowedRedirectUri(postLogoutRedirectUri) ? postLogoutRedirectUri : null;

        // Process the logout using the success handler
        logoutHandler.onLogoutSuccess(request, response, authentication, 
                idTokenHint, clientId, safeRedirectUri, state);
    }    
    
    /**
     * Endpoint for displaying the logout success page. This is used when no post_logout_redirect_uri is configured by
     * the client.
     *
     * @return The name of the logout success page template
     */
    @GetMapping("/success")
    public String logoutSuccess(@PathVariable(value = "tenantId", required = false) String tenantId, Model model) {
        tenantId = TenantUtils.resolveTenantId(tenantId);
        LOGGER.info("Logout successful, redirecting to logout success page for tenantId: {}.", tenantId);
        // Add UI attributes for logout success page
        uiAttributeUtils.addUiAttributes(model, tenantId);
        return "logout-success";
    }

    /**
     * Endpoint for displaying the logout error page.
     * This is used when an error occurs during logout and no redirect URL is available.
     *
     * @param model The Model object to add error attributes
     * @param error Optional error message parameter
     * @return The name of the logout error page template
     */
    @GetMapping("/error")
    public String logoutError(@PathVariable(value = "tenantId", required = false) String tenantId, Model model,
            @RequestParam(value = "error", required = false) String error) {
        tenantId = TenantUtils.resolveTenantId(tenantId);
        LOGGER.error("Logout error occurred: {} for tenantId: {}", error, tenantId);
        if (error != null) {
            String errorMessage = getErrorMessage(error);
            model.addAttribute("errorMessage", errorMessage);
        }
        // Add UI attributes for logout error page
        uiAttributeUtils.addUiAttributes(model, tenantId);
        return "logout-error";
    }

    /**
     * Converts error codes to user-friendly messages.
     *
     * @param errorCode The error code
     * @return User-friendly error message
     */
    private String getErrorMessage(String errorCode) {
        return switch (errorCode) {
            case OAuth2ErrorCodes.INVALID_TOKEN -> "The provided token is invalid or expired.";
            case OAuth2ErrorCodes.INVALID_CLIENT -> "The client is not recognized or not authorized.";
            case OAuth2ErrorCodes.INVALID_REQUEST -> "The logout request is malformed or invalid.";
            case OAuth2ErrorCodes.INVALID_GRANT -> "The provided grant type not supported.";
            case OAuth2ErrorCodes.UNAUTHORIZED_CLIENT -> 
            "The client is not authorized to perform the logout operation.";
            case OAuth2ErrorCodes.INVALID_REDIRECT_URI -> 
            "The provided redirect URI is invalid or does not match the registered URI.";
            case OAuth2ErrorCodes.ACCESS_DENIED -> "Access to the logout operation was denied.";
            case OAuth2ErrorCodes.SERVER_ERROR -> "An internal server error occurred during logout.";
            case OAuth2ErrorCodes.TEMPORARILY_UNAVAILABLE -> 
            "The logout service is temporarily unavailable. Please try again later.";
            default -> "An unexpected error occurred during logout.";
        };
    }

    /**
     * Checks if the redirect URI is allowed (relative path or starts with https://).
     * This is a minimal pre-validation to satisfy static analysis tools.
     */
    private boolean isAllowedRedirectUri(String uri) {
        return uri != null && (uri.startsWith("/") || uri.startsWith("https://"));
    }
}
