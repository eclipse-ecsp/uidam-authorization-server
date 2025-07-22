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
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
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

    private final UserManagementClient userManagementClient;
    private final TenantConfigurationService tenantConfigurationService;
    private final HttpServletRequest request;

    /**
     * Constructor for CustomUserPwdAuthenticationProvider.
     *
     * @param userManagementClient the user management client
     * @param tenantConfigurationService the tenant configuration service
     * @param request the HTTP servlet request
     */
    public CustomUserPwdAuthenticationProvider(UserManagementClient userManagementClient,
                                               TenantConfigurationService tenantConfigurationService,
                                               HttpServletRequest request) {
        this.userManagementClient = userManagementClient;
        this.tenantConfigurationService = tenantConfigurationService;
        this.request = request;
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
        String username = customUserPwdAuthenticationToken.getPrincipal() + "";
        String password = customUserPwdAuthenticationToken.getCredentials() + "";
        String accountName = customUserPwdAuthenticationToken.getAccountName();
        UserEvent userEvent = new UserEvent();
        userEvent.setType(IgniteOauth2CoreConstants.USER_EVENT_LOGIN_ATTEMPT);
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        int maxAllowedLoginAttempt = tenantProperties.getUser().getMaxAllowedLoginAttempts();
        LOGGER.debug("Authenticating user details for username {}", username);
        UserDetailsResponse userDetailsResponse = userManagementClient.getUserDetailsByUsername(username, accountName);
        String encryptedUserEnteredPassword = PasswordUtils.getSecurePassword(password,
            userDetailsResponse.getPasswordEncoder(), userDetailsResponse.getSalt());
        if (!encryptedUserEnteredPassword.equals(userDetailsResponse.getPassword())) {
            LOGGER.info("Password validation status: FAILED for username {}", username);
            addUserEvent(userEvent, IgniteOauth2CoreConstants.USER_EVENT_LOGIN_FAILURE,
                IgniteOauth2CoreConstants.USER_EVENT_LOGIN_FAILURE_BAD_CREDENTIALS_MSG,
                userDetailsResponse.getId());
            int loginAttempt = userDetailsResponse.getFailureLoginAttempts() + 1;

            setRecaptchaSession(loginAttempt, userDetailsResponse.getCaptcha().get(USER_CAPTCHA_REQUIRED),
                userDetailsResponse.getCaptcha().get(USER_ENFORCE_AFTER_NO_OF_FAILURES));
            if (loginAttempt >= maxAllowedLoginAttempt) {
                LOGGER.info("{} max allowed login attempt used ", maxAllowedLoginAttempt);
                throw new BadCredentialsException(USER_LOCKED_ERROR);
            }
            throw new BadCredentialsException("Bad credentials");
        }
        LOGGER.info("Password validation status: SUCCESS for username {}", username);
        addUserEvent(userEvent, IgniteOauth2CoreConstants.USER_EVENT_LOGIN_SUCCESS,
            IgniteOauth2CoreConstants.USER_EVENT_LOGIN_SUCCESS_MSG, userDetailsResponse.getId());
        List<GrantedAuthority> grantedAuthorities = userDetailsResponse.getScopes().stream()
            .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return CustomUserPwdAuthenticationToken.authenticated(username, password, accountName, grantedAuthorities);
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