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

package org.eclipse.ecsp.oauth2.server.core.authentication.handlers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.audit.context.HttpRequestContext;
import org.eclipse.ecsp.oauth2.server.core.audit.context.UserActorContext;
import org.eclipse.ecsp.oauth2.server.core.audit.enums.AuditEventType;
import org.eclipse.ecsp.oauth2.server.core.service.DatabaseSecurityContextRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.Assert;

import java.io.IOException;
import java.security.Principal;

/**
 * The CustomRevocationSuccessHandler class implements the AuthenticationSuccessHandler interface.
 * This class is used to handle successful authentication events in a Spring Security context.
 */
public class CustomRevocationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomRevocationSuccessHandler.class);
    private static final String COMPONENT_NAME = "UIDAM_AUTHORIZATION_SERVER";

    private final OAuth2AuthorizationService authorizationService;

    private final DatabaseSecurityContextRepository databaseSecurityContextRepository;

    private final AuditLogger auditLogger;

    /**
     * This is a parameterized constructor for the CustomRevocationSuccessHandler class.
     * It initializes the OAuth2AuthorizationService, DatabaseSecurityContextRepository,
     * and AuditLogger instances.
     *
     * @param authorizationService an instance of OAuth2AuthorizationService, used to interact with OAuth2
     *                             authorizations
     * @param databaseSecurityContextRepository an instance of DatabaseSecurityContextRepository, used to interact with
     *                                          the security context stored in the database
     * @param auditLogger an instance of AuditLogger, used to log audit events for token revocation
     */
    public CustomRevocationSuccessHandler(OAuth2AuthorizationService authorizationService,
                                          DatabaseSecurityContextRepository databaseSecurityContextRepository,
                                          AuditLogger auditLogger) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(databaseSecurityContextRepository, "databaseSecurityContextRepository cannot be null");
        Assert.notNull(auditLogger, "auditLogger cannot be null");
        this.authorizationService = authorizationService;
        this.databaseSecurityContextRepository = databaseSecurityContextRepository;
        this.auditLogger = auditLogger;
    }

    /**
     * This method is an override of the onAuthenticationSuccess method in the AuthenticationSuccessHandler interface.
     * It is called when a user has been successfully authenticated.
     * The method retrieves the authenticated OAuth2TokenRevocationAuthenticationToken, finds the corresponding
     * OAuth2Authorization, and checks the authorization grant type.
     * If the grant type is AUTHORIZATION_CODE, it retrieves the Principal attribute and unauthenticates the context in
     * the database.
     * Finally, it sets the response status to OK.
     *
     * @param request the HttpServletRequest associated with the authentication event
     * @param response the HttpServletResponse associated with the authentication event
     * @param authentication the Authentication object containing the details of the authenticated user
     * @throws IOException if an input or output exception occurred
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        LOGGER.debug("## onAuthenticationSuccess - START");
        OAuth2TokenRevocationAuthenticationToken tokenRevocationAuthentication =
            (OAuth2TokenRevocationAuthenticationToken) authentication;

        OAuth2Authorization authorization = this.authorizationService.findByToken(
            tokenRevocationAuthentication.getToken(), OAuth2TokenType.ACCESS_TOKEN);
        // OAuth2TokenType.ACCESS_TOKEN - Invalidate session when access token is revoked
        if (authorization == null) {
            LOGGER.info("Token not found - may be already revoked or invalid");
            logRevocationFailure(request, tokenRevocationAuthentication);
            return;
        }

        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorization.getAuthorizationGrantType())) {
            AbstractAuthenticationToken abstractAuthenticationToken = (AbstractAuthenticationToken)
                authorization.getAttribute(Principal.class.getName());
            if (abstractAuthenticationToken == null) {
                LOGGER.debug("Principal attribute not found");
                return;
            }
            WebAuthenticationDetails webAuthenticationDetails = (WebAuthenticationDetails)
                    abstractAuthenticationToken.getDetails();
            // Authenticated flag false after revoke token
            this.databaseSecurityContextRepository.unauthenticatedContextInDb(webAuthenticationDetails.getSessionId());
        }

        response.setStatus(HttpStatus.OK.value());
        LOGGER.debug("## onAuthenticationSuccess - END");
    }

    /**
     * Logs an audit event when token revocation fails because the token was not found
     * (already revoked or invalid token submitted to the user-facing /oauth2/revoke endpoint).
     *
     * @param request the HTTP request
     * @param tokenRevocationAuthentication the revocation authentication token
     */
    private void logRevocationFailure(HttpServletRequest request,
                                      OAuth2TokenRevocationAuthenticationToken tokenRevocationAuthentication) {
        try {
            String clientId = null;
            if (tokenRevocationAuthentication.getPrincipal() instanceof Authentication auth) {
                clientId = auth.getName();
            }

            UserActorContext actorContext = UserActorContext.builder()
                .userId(clientId)
                .username(null)
                .build();

            HttpRequestContext requestContext = HttpRequestContext.from(request);

            auditLogger.log(
                AuditEventType.AUTHZ_FAILURE_REVOKED_TOKEN.getType(),
                COMPONENT_NAME,
                AuditEventResult.FAILURE,
                AuditEventType.AUTHZ_FAILURE_REVOKED_TOKEN.getDescription(),
                actorContext,
                requestContext
            );

            LOGGER.debug("Audit log created for AUTHZ_FAILURE_REVOKED_TOKEN: clientId={}", clientId);
        } catch (Exception e) {
            LOGGER.error("Failed to create audit log for AUTHZ_FAILURE_REVOKED_TOKEN: {}", e.getMessage(), e);
        }
    }

}