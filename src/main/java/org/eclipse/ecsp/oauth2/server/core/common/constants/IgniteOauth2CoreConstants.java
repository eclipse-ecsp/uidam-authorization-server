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

package org.eclipse.ecsp.oauth2.server.core.common.constants;

import java.util.regex.Pattern;

/**
 * The IgniteOauth2CoreConstants class is a utility class that holds constant values used across the application.
 */
public class IgniteOauth2CoreConstants {


    private IgniteOauth2CoreConstants() {
        
    }
    
    public static final String ADMIN = "ADMIN";

    public static final String CLAIM_AUT_APP_USER = "APPLICATION_USER";
    public static final String CLAIM_AUT_APP = "APPLICATION";
    public static final String CLAIM_SCOPES = "scopes";
    public static final String CLAIM_USER_ID = "user_id";
    public static final String CLAIM_USERNAME = "username";
    // To confirm
    public static final String CLAIM_ORIGINAL_USERNAME = "original_username";
    public static final String CLAIM_ACCOUNT_ID = "accountId";
    public static final String CLAIM_ACCOUNT_NAME = "accountName";
    public static final String CLAIM_ACCOUNT_TYPE = "accountType";
    public static final String CLAIM_LAST_LOGON = "last_logon";
    public static final String CLAIM_FIRST_NAME = "firstName";
    public static final String CLAIM_LAST_NAME = "lastName";

    public static final String CLAIM_USER_ROLES = "roles";

    public static final String CLAIM_TENANT_ID = "tenantId";

    public static final String CLAIM_ORIGINAL_USER_ID = "originalUserId";
    public static final String CLAIM_HEADER_TYPE = "typ";
    public static final String CLAIM_HEADER_JWT_ACCESS_TOKEN_TYPE = "at+jwt";
    public static final String CLAIM_HEADER_ID_TOKEN_TYPE = "id+jwt";

    public static final String MSG_DIGEST_ALGORITHM = "SHA-256";
    public static final String AUTHORIZATION_CODE_GRANT_TYPE = "authorization_code";
    public static final String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
    public static final String REFRESH_TOKEN_GRANT_TYPE = "refresh_token";
    public static final String DATE_FORMAT = "y-M-d'T'H:m:sX";
    public static final String ACCOUNT_NAME_HEADER = "accountName";
    public static final String TENANT_ID_HEADER = "tenantId";
    public static final String SPRING_SECURITY_FORM_ACCOUNT_NAME_KEY = "account_name";

    public static final String SPRING_SECURITY_FORM_RECAPTCHA_RESPONSE_KEY = "g-recaptcha-response";
    public static final String EMPTY_STRING = "";
    public static final String ACCOUNT_FIELD_ENABLED = "isAccountFieldEnabled";
    public static final String CAPTCHA_FIELD_ENABLED = "isCaptchaFieldEnabled";
    public static final String CAPTCHA_SITE = "captchaSite";

    public static final String REVOKE_TOKEN_SUCCESS_RESPONSE = "Token revoked successfully!";
    public static final String NO_ACTIVE_TOKEN_EXIST = "No active token exist for the provided id!";
    public static final String REVOKE_TOKEN_SCOPE = "RevokeToken";
    public static final String SELF_MANAGE_SCOPE = "SelfManage";
    public static final String MANAGE_USERS_SCOPE = "ManageUsers";
    public static final String BEARER = "Bearer";
    public static final String USER_STATUS_ACTIVE = "ACTIVE";
    public static final String USER_STATUS_BLOCKED = "BLOCKED";
    public static final String CORRELATION_ID = "correlationId";
    public static final String USER_EVENT_LOGIN_ATTEMPT = "LOGIN_ATTEMPT";
    public static final String USER_EVENT_LOGIN_SUCCESS = "SUCCESS";
    public static final String USER_EVENT_LOGIN_FAILURE = "FAILURE";
    public static final String USER_EVENT_LOGIN_FAILURE_BAD_CREDENTIALS_MSG = "Bad Credentials";
    public static final String USER_EVENT_LOGIN_SUCCESS_MSG = "User Logged in successfully!";

    public static final String SINGLE_ROLE_CLIENT = "single_role";
    public static final String MULTI_ROLE_CLIENT = "multi_role";
    public static final String SESSION_USER_RESPONSE_CAPTCHA_ENABLED = "userResponseCaptchaEnabled";
    public static final String SESSION_USER_RESPONSE_ENFORCE_AFTER_NO_OF_FAILURES =
        "userResponseEnforceAfterNoOfFailures";

    public static final String LOGIN_ATTEMPT = "loginAttempt";
    public static final int MAX_RECAPTCHA_CLIENT_FAILED_ATTEMPT = 4;
    public static final String COMMA_DELIMITER = ",";
    public static final String USER_CAPTCHA_REQUIRED = "required";
    public static final String USER_ENFORCE_AFTER_NO_OF_FAILURES = "enforceAfterNoOfFailures";

    public static final Pattern RESPONSE_PATTERN = Pattern.compile("[A-Za-z0-9_-]+");

    public static final String RECAPTCHA_URL_TEMPLATE = "?secret=%s&response=%s&remoteip=%s";
    public static final int ITERATION_COUNT = 65536;
    public static final String LOGIN_FAILURE_HANDLER = "/login?error=true";
    public static final String LOGIN_HANDLER = "/login";
    public static final String LOGOUT_HANDLER = "/oauth2/logout";
    public static final String LOGOUT_MATCHER_PATTERN = "/*/oauth2/logout/**";
    public static final String LOGIN_MATCHER_PATTERN = "/*/login/**";
    public static final String DEFAULT_LOGIN_MATCHER_PATTERN = "/login/**";
    public static final String REQUEST_MATCHER_PATTERN = "/*/oauth2/**";
    public static final int INITIAL_ODD_NUMBER = 17;
    public static final int MULTIPLIER_ODD_NUMBER = 37;
    
    public static final String USER_DETAILS_NOT_FOUND = "If an account with this username exists, "
            + "then you shall receive instructions for resetting the password.";
    public static final String EMAIL_NOT_DEFINED = "Email has not been defined in the system."
            + "\n Password recovery is not possible.";
    public static final String PASSWORD_RECOVERY_EMAIL_SENT = "A reset password link has been"
            + " sent to your registered email.";
    public static final String INVALID_SECRET_PROVIDED = "Invalid secret provided.\n "
            + "Password recovery is not possible.";
    public static final String PASSWORD_DID_NOT_MATCH = "Passwords did not match!";
    public static final String PASSWORD_UPDATED_SUCCESSFULLY = "Your password has been changed successfully.";
    public static final String PASSWORD_RECOVERY_EMAIL_SENT_FAILURE = "Failed to send "
            + "reset password link to your email.";

    public static final String INTERNAL_LOGIN_ENABLED = "isInternalLoginEnabled";

    public static final String EXTERNAL_IDP_ENABLED = "isExternalIdpEnabled";
    public static final String IS_IDP_AUTO_REDIRECTION_ENABLED = "isIDPAutoRedirectionEnabled";
    public static final String IS_SIGN_UP_ENABLED = "isSignUpEnabled";
    public static final String EXTERNAL_IDP_LIST = "externalIdpList";
    public static final String EXTERNAL_IDP_AUTHORIZATION_URI = "externalIdpAuthorizationUri";
    public static final String IDP_REDIRECT_URI = "/login/oauth2/code/";
    public static final String IDP_AUTHORIZATION_URI = "/oauth2/authorization/";
    public static final String FETCH_INTERNAL_USER = "FETCH_INTERNAL_USER";
    public static final String CREATE_USER_MODE = "CREATE_INTERNAL_USER";
    public static final String USER_NOT_FOUND = "USER_NOT_FOUND";
    public static final String AUTHORIZATION_TABLE = "Authorization";
    public static final String ACC_NAME_REGEX = "^[a-zA-Z0-9]+$";
    public static final String ACC_NAME_FORMAT_ERROR = "Invalid Account Name format.";

    public static final String ERROR_LITERAL = "error";
    public static final String MSG_LITERAL = "message";
    public static final String PWD_NOTE = "pwdNote";
    public static final String MIN_LENGTH = "pwdMin";
    public static final String MAX_LENGTH = "pwdMax";
    public static final String MIN_CON_LETTERS = "minConsecutiveLettersLength";
    public static final String MIN_SPECIALCHARS = "minSpecialChars";
    public static final String ALLOWED_SPECIALCHARS = "allowedSpecialChars";
    public static final String EXCLUDED_SPECIALCHARS = "excludedSpecialChars";
    public static final String MIN_UPPERCASE = "minUppercase";
    public static final String MIN_LOWERCASE = "minLowercase";
    public static final String MIN_DIGITS = "minDigits";
    public static final boolean TRUE = true;

    public static final String ERROR_WHILE_BUILDING_REDIRECT_URI = "Error while building redirect URI: ";

    public static final String CLIENT_CACHE_VALUE = "client";
    public static final String CLIENT_CACHE_KEY = "#tenantId + ':' + #clientId";
    public static final String CLIENT_CACHE_UNLESS = "#result == null || #result.cache == false";

    public static final String ID_PREFIX = "{";
    public static final String ID_SUFFIX = "}";
    public static final String NOOP_ID_ENCODE = "noop";
    public static final String BCRYPT_ID_ENCODE = "bcrypt";
    
    public static final String ISSUER_PARAM_NAME = "issuer";

    // UI Configuration constants
    public static final String TENANT_LOGO_PATH = "tenantLogoPath";
    public static final String TENANT_STYLESHEET_PATH = "tenantStylesheetPath";

}