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

package org.eclipse.ecsp.oauth2.server.core.service;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.BooleanUtils;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.LOGIN_ATTEMPT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SESSION_USER_RESPONSE_CAPTCHA_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES;

/**
 * This is a service class that handles login functionalities.
 */
@Service
public class LoginService {

    private final TenantConfigurationService tenantConfigurationService;
    private final HttpServletRequest request;

    /**
     * Constructor for LoginService.
     * It initializes the service with the tenant configuration service for dynamic tenant resolution.
     *
     * @param tenantConfigurationService the service to retrieve tenant properties from
     * @param request the HTTP servlet request
     */
    @Autowired
    public LoginService(TenantConfigurationService tenantConfigurationService, HttpServletRequest request) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.request = request;
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginService.class);

    /**
     * This method checks if captcha is enabled for the User Interface.
     * It first checks if captcha is required as per the tenant properties.
     * If required, it further checks if captcha is enabled after a certain number of invalid failures.
     * If not required, it returns false indicating that captcha is not enabled.
     *
     * @return boolean flag indicating whether captcha is enabled or not
     */
    public boolean isCaptchaEnabledForUserInterface() {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        boolean isCaptchaEnabled;
        if (BooleanUtils.isTrue(tenantProperties.getUser().getCaptchaRequired())) {
            LOGGER.debug("Captcha Enabled for Tenant");
            if (tenantProperties.getUser().getCaptchaAfterInvalidFailures() != 0) {
                isCaptchaEnabled = isCaptchaEnabledAfterTenantLevelInvalidFailuresCountNonZero();
            } else {
                LOGGER.debug("Captcha always enabled for Tenant");
                isCaptchaEnabled = true;
            }
        } else {
            LOGGER.debug("Captcha disabled for Tenant");
            isCaptchaEnabled = false;
        }
        return isCaptchaEnabled;
    }

    /**
     * This method checks if captcha is enabled after a certain number of invalid login attempts at the tenant level.
     * It checks if captcha is enabled post user login and returns the result.
     *
     * @return boolean flag indicating whether captcha is enabled or not after tenant level invalid failures
     */
    private boolean isCaptchaEnabledAfterTenantLevelInvalidFailuresCountNonZero() {
        boolean isCaptchaEnabled;
        LOGGER.debug("CaptchaAfterInvalidFailures not zero");

        boolean isCaptchaEnabledPostUserLogin = isCaptchaEnabledPostUserLogin();

        if (!isCaptchaEnabledPostUserLogin) {
            LOGGER.debug("[USER]: Captcha disabled for User");
            isCaptchaEnabled = false;
        } else {
            LOGGER.debug("[USER]: Captcha enabled for User");
            isCaptchaEnabled = true;
        }
        return isCaptchaEnabled;
    }

    /**
     * This method checks if captcha is enabled post user login.
     * It retrieves the login attempt count, user level captcha enabled flag, and enforce after no of failures count
     * from the session.
     * Based on these values, it determines if captcha should be enforced and returns the result.
     *
     * @return boolean flag indicating whether captcha is enabled post user login
     */
    private boolean isCaptchaEnabledPostUserLogin() {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        boolean isCaptchaEnabled = false;

        Integer loginAttempt = request.getSession().getAttribute(LOGIN_ATTEMPT) != null
                ? (Integer) request.getSession().getAttribute(LOGIN_ATTEMPT)
                : null;
        Boolean isUserLevelCaptchaEnabled = request.getSession()
                .getAttribute(SESSION_USER_RESPONSE_CAPTCHA_ENABLED) != null
                ? (Boolean) request.getSession().getAttribute(SESSION_USER_RESPONSE_CAPTCHA_ENABLED)
                : null;
        Integer enforceAfterNoOfFailuresFromUserResponse = request.getSession()
                .getAttribute(SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES) != null
                ? (Integer) request.getSession().getAttribute(SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES)
                : null;

        if (null == isUserLevelCaptchaEnabled) {
            isCaptchaEnabled = isCaptchaEnforcedAsPerLoginAttempts(loginAttempt,
                    tenantProperties.getUser().getCaptchaAfterInvalidFailures());
        } else if (BooleanUtils.isTrue(isUserLevelCaptchaEnabled)) {
            Integer enforceAfterNoOfFailures = null != enforceAfterNoOfFailuresFromUserResponse
                    ? enforceAfterNoOfFailuresFromUserResponse
                    : tenantProperties.getUser().getCaptchaAfterInvalidFailures();
            isCaptchaEnabled = isCaptchaEnforcedAsPerLoginAttempts(loginAttempt, enforceAfterNoOfFailures);
        } else {
            LOGGER.info("[USER]: Captcha not enabled");
        }
        return isCaptchaEnabled;
    }

    /**
     * This method checks if captcha should be enforced based on the number of login attempts and the enforce after no
     * of failures count.
     * If the login attempt count is greater than or equal to the enforce after no of failures count, it returns true
     * indicating that captcha should be enforced.
     * Otherwise, it returns false.
     *
     * @param loginAttempt the number of login attempts
     * @param enforceAfterNoOfFailures the count after which captcha should be enforced
     * @return boolean flag indicating whether captcha should be enforced
     */
    private boolean isCaptchaEnforcedAsPerLoginAttempts(Integer loginAttempt, Integer enforceAfterNoOfFailures) {
        boolean isCaptchaEnabled = false;

        if ((null != loginAttempt && null != enforceAfterNoOfFailures)
                && (loginAttempt >= enforceAfterNoOfFailures)) {
            LOGGER.info("[USER]: Captcha enabled");
            isCaptchaEnabled = true;
        } else {
            LOGGER.info("[USER]: Captcha not enabled");
        }
        return isCaptchaEnabled;
    }

    /**
     * This method checks if auto redirection is enabled for authentication.
     * Auto redirection is considered enabled if there is exactly one external identity provider registered for the
     * tenant.
     * If there are multiple external identity providers or none, auto redirection is considered disabled.
     *
     * @return true if auto redirection is enabled, false otherwise
     */
    public boolean isAutoRedirectionEnabled() {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        return tenantProperties.getExternalIdpRegisteredClientList().size() == 1;
    }
}
