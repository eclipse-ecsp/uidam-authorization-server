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

package org.eclipse.ecsp.oauth2.server.core.authentication.filters;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.exception.PatternMismatchException;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.service.impl.CaptchaServiceImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.EMPTY_STRING;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SPRING_SECURITY_FORM_ACCOUNT_NAME_KEY;
import static org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils.isAccountNamePatternValid;
import static org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils.obtainRecaptchaResponse;

/**
 * CustomUserPwdAuthenticationFilter is a class that extends the UsernamePasswordAuthenticationFilter class provided by
 * Spring Security. It is used to handle authentication requests where the user provides their username and password.
 * The class also includes additional functionality for handling account names and reCAPTCHA responses.
 */
public class CustomUserPwdAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private String accountNameParameter = SPRING_SECURITY_FORM_ACCOUNT_NAME_KEY;

    private CaptchaServiceImpl captchaServiceImpl;
    private boolean postOnly = true;

    /**
     * Constructor for the CustomUserPwdAuthenticationFilter class.
     * It initializes the AuthenticationManager and the CaptchaServiceImpl.
     *
     * @param authenticationManager The AuthenticationManager to be used for authenticating requests.
     * @param tenantConfigurationService The TenantConfigurationService to be used for configuring tenants.
     * @param authorizationMetricsService The AuthorizationMetricsService to be used for metrics collection.
     * @param auditLogger The AuditLogger for logging authentication events.
     */
    public CustomUserPwdAuthenticationFilter(AuthenticationManager authenticationManager,
                                             TenantConfigurationService tenantConfigurationService,
                                             AuthorizationMetricsService authorizationMetricsService,
                                             AuditLogger auditLogger) {
        super(authenticationManager);
        captchaServiceImpl = new CaptchaServiceImpl(tenantConfigurationService, authorizationMetricsService,
                                                    auditLogger);
    }

    /**
     * This method attempts to authenticate a user based on the provided HttpServletRequest and HttpServletResponse.
     * It first checks if the request method is POST, throwing an AuthenticationServiceException if it's not.
     * Then, it retrieves the username, password, account name, and reCAPTCHA response from the request.
     * If a reCAPTCHA response is present, it processes the response.
     * Finally, it creates a CustomUserPwdAuthenticationToken with the retrieved details and attempts to authenticate
     * the user.
     *
     * @param request the HttpServletRequest containing the user's authentication details
     * @param response the HttpServletResponse where the result of the authentication attempt will be written
     * @return an Authentication object representing the authenticated user
     * @throws AuthenticationException if the authentication attempt fails
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException {
        if (this.postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        String username = obtainUsername(request);
        username = (username != null) ? username.trim() : EMPTY_STRING;
        String password = obtainPassword(request);
        password = (password != null) ? password : EMPTY_STRING;
        String accountName = obtainAccountName(request);
        accountName = (accountName != null) ? accountName : EMPTY_STRING;

        try {
            isAccountNamePatternValid(accountName);
        } catch (PatternMismatchException e) {
            throw new AuthenticationServiceException(e.getMessage());
        }

        String recaptchaResponse = obtainRecaptchaResponse(request);
        recaptchaResponse = (recaptchaResponse != null) ? recaptchaResponse : EMPTY_STRING;
        if (StringUtils.hasText(recaptchaResponse)) {
            captchaServiceImpl.processResponse(recaptchaResponse, request);
        }
        CustomUserPwdAuthenticationToken authRequest = CustomUserPwdAuthenticationToken.unauthenticated(username,
                password, accountName);
        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * This method retrieves the account name from the HttpServletRequest.
     * The account name is retrieved as a parameter from the request.
     *
     * @param request the HttpServletRequest from which to retrieve the account name
     * @return the account name as a String
     */
    protected String obtainAccountName(HttpServletRequest request) {
        return request.getParameter(this.accountNameParameter);
    }
}