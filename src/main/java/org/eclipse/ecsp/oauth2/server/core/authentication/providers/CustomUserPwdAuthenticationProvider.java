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

package org.eclipse.ecsp.oauth2.server.core.authentication.providers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.audit.context.HttpRequestContext;
import org.eclipse.ecsp.oauth2.server.core.audit.context.PasswordAuthenticationContext;
import org.eclipse.ecsp.oauth2.server.core.audit.context.UserActorContext;
import org.eclipse.ecsp.oauth2.server.core.audit.enums.AuditEventType;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.metrics.MetricType;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserEvent;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.PasswordUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_ATTEMPT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SESSION_USER_RESPONSE_CAPTCHA_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.USER_CAPTCHA_REQUIRED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.USER_ENFORCE_AFTER_NO_OF_FAILURES;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.ResponseMessages.USER_LOCKED_ERROR;

/**
 * The CustomUserPwdAuthenticationProvider class implements the AuthenticationProvider interface from Spring Security.
 * It is responsible for handling user password authentication.
 */
@Component
public class CustomUserPwdAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomUserPwdAuthenticationProvider.class);
    private static final String COMPONENT_NAME = "UIDAM_AUTHORIZATION_SERVER";

    private final UserManagementClient userManagementClient;
    private final TenantConfigurationService tenantConfigurationService;
    private final HttpServletRequest request;
    private final AuthorizationMetricsService metricsService;
    private final AuditLogger auditLogger;

    /**
     * Constructor for CustomUserPwdAuthenticationProvider.
     *
     * @param userManagementClient the user management client
     * @param tenantConfigurationService the tenant configuration service
     * @param request the HTTP servlet request
     * @param metricsService the authorization metrics service
     * @param auditLogger the audit logger
     */
    public CustomUserPwdAuthenticationProvider(UserManagementClient userManagementClient,
                                               TenantConfigurationService tenantConfigurationService,
                                               HttpServletRequest request,
                                               AuthorizationMetricsService metricsService,
                                               AuditLogger auditLogger) {
        this.userManagementClient = userManagementClient;
        this.tenantConfigurationService = tenantConfigurationService;
        this.request = request;
        this.metricsService = metricsService;
        this.auditLogger = auditLogger;
    }

    /**
     * This method overrides the authenticate method from the AuthenticationProvider interface.
     * It is called when a user attempts to authenticate.
     * The method retrieves the user details from the UserManagementClient, validates the user's password, and if the
     * password is valid, it creates a new authenticated CustomUserPwdAuthenticationToken with the user's details and
     * granted authorities.
     * If the password is not valid, it increments the user's failed login attempts, sets the recaptcha session
     * attributes, and throws a BadCredentialsException.
     *
     * @param authentication the Authentication object containing the details of the authentication request
     * @return an authenticated CustomUserPwdAuthenticationToken if the authentication is successful
     * @throws AuthenticationException if the authentication fails
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomUserPwdAuthenticationToken customUserPwdAuthenticationToken =
            (CustomUserPwdAuthenticationToken) authentication;
        UserEvent userEvent = new UserEvent();
        userEvent.setType(IgniteOauth2CoreConstants.USER_EVENT_LOGIN_ATTEMPT);
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        int maxAllowedLoginAttempt = tenantProperties.getUser().getMaxAllowedLoginAttempts();
        String tenantId = tenantProperties.getTenantId();
        String username = customUserPwdAuthenticationToken.getPrincipal() + "";
        String accountName = customUserPwdAuthenticationToken.getAccountName();
        LOGGER.debug("Authenticating user details for username {}", username);
        metricsService.incrementMetricsForTenant(tenantId, MetricType.TOTAL_LOGIN_ATTEMPTS);
        
        UserDetailsResponse userDetailsResponse;
        try {
            userDetailsResponse = userManagementClient.getUserDetailsByUsername(username, accountName);
        } catch (OAuth2AuthenticationException ex) {
            logAuthenticationException(ex, username, accountName);
            throw ex;
        }
        String password = customUserPwdAuthenticationToken.getCredentials() + "";
        String encryptedUserEnteredPassword = PasswordUtils.getSecurePassword(password,
            userDetailsResponse.getPasswordEncoder(), userDetailsResponse.getSalt());
        if (!encryptedUserEnteredPassword.equals(userDetailsResponse.getPassword())) {
            LOGGER.info("Password validation status: FAILED for username {}", username);
            metricsService.incrementMetricsForTenant(tenantId,
                                                    MetricType.FAILURE_LOGIN_WRONG_PASSWORD,
                                                    MetricType.FAILURE_LOGIN_ATTEMPTS);
            addUserEvent(userEvent, IgniteOauth2CoreConstants.USER_EVENT_LOGIN_FAILURE,
                IgniteOauth2CoreConstants.USER_EVENT_LOGIN_FAILURE_BAD_CREDENTIALS_MSG,
                userDetailsResponse.getId());
            int loginAttempt = userDetailsResponse.getFailureLoginAttempts() + 1;
            
            logFailedAuthentication(userDetailsResponse, username, accountName, 
                AuditEventType.AUTH_FAILURE_WRONG_PASSWORD, loginAttempt);

            setRecaptchaSession(loginAttempt, userDetailsResponse.getCaptcha().get(USER_CAPTCHA_REQUIRED),
                userDetailsResponse.getCaptcha().get(USER_ENFORCE_AFTER_NO_OF_FAILURES));
            if (loginAttempt >= maxAllowedLoginAttempt) {
                LOGGER.info("{} max allowed login attempt used ", maxAllowedLoginAttempt);
                metricsService.incrementMetricsForTenant(tenantId,
                                                        MetricType.FAILURE_LOGIN_USER_BLOCKED,
                                                        MetricType.FAILURE_LOGIN_ATTEMPTS);
                logFailedAuthentication(userDetailsResponse, username, accountName,
                    AuditEventType.AUTH_FAILURE_ACCOUNT_LOCKED, loginAttempt);
                throw new BadCredentialsException(USER_LOCKED_ERROR);
            }
            throw new BadCredentialsException("Bad credentials");
        }
        LOGGER.info("Password validation status: SUCCESS for username {}", username);
        metricsService.incrementMetricsForTenant(tenantId, MetricType.SUCCESS_LOGIN_ATTEMPTS);
        addUserEvent(userEvent, IgniteOauth2CoreConstants.USER_EVENT_LOGIN_SUCCESS,
            IgniteOauth2CoreConstants.USER_EVENT_LOGIN_SUCCESS_MSG, userDetailsResponse.getId());
        
        logSuccessfulAuthentication(userDetailsResponse, username, accountName);
        
        List<GrantedAuthority> grantedAuthorities = userDetailsResponse.getScopes().stream()
            .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return CustomUserPwdAuthenticationToken.authenticated(username, password, accountName, grantedAuthorities);
    }
    
    private void logSuccessfulAuthentication(UserDetailsResponse userDetailsResponse,
                                            String username,
                                            String accountName) {
        try {
            String accountIdStr = userDetailsResponse.getAccountId();
            
            UserActorContext actorContext = UserActorContext.builder()
                .userId(userDetailsResponse.getId())
                .username(username)
                .accountId(accountIdStr)
                .accountName(accountName)
                .build();
            
            HttpRequestContext requestContext = HttpRequestContext.from(request);
            
            auditLogger.log(
                AuditEventType.AUTH_SUCCESS_PASSWORD.getType(),
                COMPONENT_NAME,
                AuditEventResult.SUCCESS,
                AuditEventType.AUTH_SUCCESS_PASSWORD.getDescription(),
                actorContext,
                requestContext
            );
            
            LOGGER.debug("Audit log created for AUTH_SUCCESS_PASSWORD: userId={}", userDetailsResponse.getId());
        } catch (Exception e) {
            LOGGER.error("Failed to create audit log for AUTH_SUCCESS_PASSWORD: {}", e.getMessage(), e);
        }
    }
    
    private void logFailedAuthentication(UserDetailsResponse userDetailsResponse,
                                        String username,
                                        String accountName,
                                        AuditEventType eventType,
                                        int failedAttempts) {
        try {
            String accountIdStr = userDetailsResponse.getAccountId();
            
            UserActorContext actorContext = UserActorContext.builder()
                .userId(userDetailsResponse.getId())
                .username(username)
                .accountId(accountIdStr)
                .accountName(accountName)
                .build();
            
            HttpRequestContext requestContext = HttpRequestContext.from(request);
            
            PasswordAuthenticationContext authContext = PasswordAuthenticationContext.builder()
                .failedAttempts(failedAttempts)
                .authType("password")
                .build();
            
            auditLogger.log(
                eventType.getType(),
                COMPONENT_NAME,
                AuditEventResult.FAILURE,
                eventType.getDescription(),
                actorContext,
                null,  // TargetContext
                requestContext,
                authContext
            );
            
            LOGGER.debug("Audit log created for {}: userId={}, failedAttempts={}", 
                eventType, userDetailsResponse.getId(), failedAttempts);
        } catch (Exception e) {
            LOGGER.error("Failed to create audit log for {}: {}", eventType, e.getMessage(), e);
        }
    }
    
    private void logAuthenticationException(OAuth2AuthenticationException ex, 
                                           String username, 
                                           String accountName) {
        try {
            String errorCode = ex.getError().getErrorCode();
            AuditEventType eventType;
            
            if ("USER_NOT_FOUND".equals(errorCode)) {
                eventType = AuditEventType.AUTH_FAILURE_USER_NOT_FOUND;
            } else if ("USER_NOT_ACTIVE".equals(errorCode)) {
                eventType = AuditEventType.AUTH_FAILURE_USER_BLOCKED;
            } else if ("ACCOUNT_NOT_FOUND".equals(errorCode)) {
                eventType = AuditEventType.AUTH_FAILURE_ACCOUNT_NOT_FOUND;
            } else {
                // Generic authentication failure - don't audit unknown error codes
                return;
            }
            
            // For user not found/blocked, we don't have userId
            UserActorContext actorContext = UserActorContext.builder()
                .username(username)
                .accountName(accountName)
                .build();
            
            HttpRequestContext requestContext = HttpRequestContext.from(request);
            
            auditLogger.log(
                eventType.getType(),
                COMPONENT_NAME,
                AuditEventResult.FAILURE,
                ex.getError().getDescription(),
                actorContext,
                requestContext
            );
            
            LOGGER.debug("Audit log created for {}: username={}", eventType, username);
        } catch (Exception e) {
            LOGGER.error("Failed to create audit log for authentication exception: {}", e.getMessage(), e);
        }
    }

    /**
     * This private method named addUserEvent is used to add a user event.
     * It is called when a user's login attempt is either successful or failed.
     * The method takes a UserEvent object, a status string, a message string, and a userId string as parameters.
     * It sets the result and message of the UserEvent object and calls the addUserEvent method of the
     * UserManagementClient with the UserEvent object and userId.
     *
     * @param userEvent the UserEvent object to be added
     * @param status the status of the user event
     * @param message the message of the user event
     * @param userId the id of the user
     */
    private void addUserEvent(UserEvent userEvent, String status, String message, String userId) {
        userEvent.setResult(status);
        userEvent.setMessage(message);
        userManagementClient.addUserEvent(userEvent, userId);
    }

    /**
     * This method overrides the supports method from the AuthenticationProvider interface.
     * It checks if the provided authentication class is assignable from the CustomUserPwdAuthenticationToken class.
     *
     * @param authentication the Class object representing the authentication class
     * @return true if the provided authentication class is assignable from the CustomUserPwdAuthenticationToken class,
     *         false otherwise
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return (CustomUserPwdAuthenticationToken.class.isAssignableFrom(authentication));
    }

    /**
     * This private method sets the recaptcha session attributes.
     * It is called when a user's login attempt fails.
     *
     * @param loginAttempt the number of failed login attempts
     * @param userResponseCaptchaEnabled the captcha enabled status from the user response
     * @param userResponseEnforceAfterNoOfFailures the enforce after no of failures status from the user response
     */
    private void setRecaptchaSession(int loginAttempt, Object userResponseCaptchaEnabled,
                                     Object userResponseEnforceAfterNoOfFailures) {
        HttpSession session = request.getSession();
        session.setAttribute(LOGIN_ATTEMPT, loginAttempt);

        session.setAttribute(SESSION_USER_RESPONSE_CAPTCHA_ENABLED, userResponseCaptchaEnabled);
        session.setAttribute(SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES, userResponseEnforceAfterNoOfFailures);
    }

}