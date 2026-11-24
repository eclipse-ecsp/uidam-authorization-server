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

package org.eclipse.ecsp.oauth2.server.core.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.BooleanUtils;
import org.eclipse.ecsp.oauth2.server.core.exception.PatternMismatchException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.util.StringUtils;

import java.util.Locale;
import java.util.Set;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ACC_NAME_FORMAT_ERROR;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ACC_NAME_REGEX;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MULTI_ROLE_CLIENT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SPRING_SECURITY_FORM_RECAPTCHA_RESPONSE_KEY;

/**
 * The CommonMethodsUtils class is a utility class that provides common methods to be used across the project.
 */
public class CommonMethodsUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(CommonMethodsUtils.class);

    private static final Set<String> OIDC_SCOPES = Set.of(OidcScopes.OPENID, OidcScopes.PROFILE,
            OidcScopes.EMAIL, OidcScopes.PHONE, OidcScopes.ADDRESS);

    private CommonMethodsUtils() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Checks whether a name is reserved for authentication-factor authorities ({@code FACTOR_*}).
     * Such names must only be issued by trusted authentication steps, never sourced from user data.
     *
     * @param authority authority or scope name
     * @return true when the name uses the reserved factor prefix
     */
    public static boolean isReservedFactorAuthority(String authority) {
        return authority != null && authority.trim().toUpperCase(Locale.ROOT).startsWith("FACTOR_");
    }

    /**
     * Checks whether a non-empty scope request contains only standard OIDC scopes.
     *
     * @param scopes requested scopes
     * @return true when every requested scope is an OIDC scope
     */
    public static boolean isOidcOnlyScopeRequest(Set<String> scopes) {
        return scopes != null && !scopes.isEmpty() && OIDC_SCOPES.containsAll(scopes);
    }

    /**
     * This method checks if validation of a user's scope is required.
     * It checks the client type and a flag indicating if tenant level scope customization is required.
     * If the client type is MULTI_ROLE_CLIENT, or if the flag is true, it sets the return value to false.
     * Otherwise, it sets the return value to true.
     *
     * @param clientType the client type on which the check relies on.
     * @param isOauthScopeCustomizationRequired a flag to determine if tenant level scope customization is required.
     * @return a boolean flag indicating if user scope validation is required.
     */
    public static boolean isUserScopeValidationRequired(String clientType, Boolean isOauthScopeCustomizationRequired) {
        boolean isUserScopeValidationRequired = true;
        if (StringUtils.hasText(clientType)) {
            if (clientType.equals(MULTI_ROLE_CLIENT)) {
                LOGGER.debug("Multi-Role: Scope Validation for user not"
                    + " required and scope/scopes bifurcation required");
                isUserScopeValidationRequired = false;
            }
        } else {
            if (BooleanUtils.isTrue(isOauthScopeCustomizationRequired)) {
                LOGGER.debug("tenant.client.oauth-scope-customization = true: Scope Validation for user not "
                    + "required and scope/scopes bifurcation required");
                isUserScopeValidationRequired = false;
            }
        }
        return isUserScopeValidationRequired;
    }

    /**
     * Validates the account name against a predefined pattern.
     * If the account name does not match the pattern, a PatternMismatchException is thrown.
     *
     * @param accountName the account name to be validated
     * @throws PatternMismatchException if the account name does not match the predefined pattern
     */
    public static void isAccountNamePatternValid(String accountName) {
        if (StringUtils.hasText(accountName) && !accountName.matches(ACC_NAME_REGEX)) {
            throw new PatternMismatchException(ACC_NAME_FORMAT_ERROR);
        }
    }

    /**
     * This method retrieves the reCAPTCHA response from the HttpServletRequest.
     * The reCAPTCHA response is retrieved as a parameter from the request.
     *
     * @param request the HttpServletRequest from which to retrieve the reCAPTCHA response
     * @return the reCAPTCHA response as a String
     */
    public static String obtainRecaptchaResponse(HttpServletRequest request) {
        return request.getParameter(SPRING_SECURITY_FORM_RECAPTCHA_RESPONSE_KEY);
    }
}
