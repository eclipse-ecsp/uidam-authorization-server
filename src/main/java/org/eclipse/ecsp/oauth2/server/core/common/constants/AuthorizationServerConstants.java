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

/**
 * The AuthorizationServerConstants class is a utility class that holds constant values used across the application.
 */
public final class AuthorizationServerConstants {



    private AuthorizationServerConstants() {

    }

    public static final String ECSP = "ecsp";
    public static final String TENANT_CONTACT_NAME = "contact-name";
    public static final String TENANT_PHONE_NUMBER = "phone-number";
    public static final String TENANT_EMAIL = "email";
    public static final String TENANT_EXTERNAL_IDP_CLIENT_ID = "client-id";
    public static final String TENANT_EXTERNAL_IDP_CLIENT_SECRET = "client-secret";

    // external url endpoints
    public static final String TENANT_EXTERNAL_URLS_USER_BY_USERNAME_ENDPOINT = "user-by-username-endpoint";
    public static final String TENANT_EXTERNAL_URLS_ADD_USER_EVENTS_ENDPOINT = "add-user-events-endpoint";
    public static final String TENANT_EXTERNAL_URLS_USER_RECOVERY_NOTIF_ENDPOINT = "user-recovery-notif-endpoint";
    public static final String TENANT_EXTERNAL_URLS_USER_RESET_PASSWORD_ENDPOINT = "reset-password-endpoint";
    public static final String TENANT_EXTERNAL_URLS_CLIENT_BY_CLIENT_ID_ENDPOINT = "client-by-client-id-endpoint";
    public static final String TENANT_EXTERNAL_URLS_USER_MANAGEMENT_ENV = "user-management-base-url";
    public static final String TENANT_EXTERNAL_URLS_SELF_CREATE_USER = "self-create-user-endpoint";
    public static final String TENANT_EXTERNAL_URLS_CREATE_FEDRATED_USER = "create-fedrated-user-endpoint";
    public static final String TENANT_EXTERNAL_URLS_PASSWORD_POLICY_ENDPOINT = "password-policy-endpoint";

    public static final String TENANT_KEYSTORE_FILENAME = "key-store-filename";
    public static final String TENANT_KEYSTORE_PASS = "key-store-password";
    public static final String TENANT_KEYSTORE_ALIAS = "key-alias";
    public static final String TENANT_KEYSTORE_TYPE = "key-type";
    public static final String TENANT_JWT_PUBLIC_KEY = "jwt-public-key";
    public static final String TENANT_JWT_PRIVATE_KEY = "jwt-private-key";
    public static final String TENANT_JWT_KEY_ID = "jwt-key-id";
    public static final String TENANT_JWT_PUBLIC_KEY_PEM_PATH = "jwt-public-key-path";
    public static final String TENANT_JWT_ADDITIONAL_CLAIM_ATTRIBUTES = "jwt-additional-claim-attributes";
    public static final String SUCCESS = "success";
    public static final String BAD_REQUEST_LITERAL = "BAD_REQUEST";
    public static final String SECRET_LITERAL = "secret";
    public static final String PASSWORD = "Password";
    public static final String SLASH = "/";
    public static final int DEFAULT_MIN_LENGTH = 10;
    public static final int DEFAULT_MAX_LENGTH = 50;
    public static final String DEFAULT_ALLOWEDSPECIALCHARS = "!@#$%^&*()_-+=<>?";
    public static final String DEFAULT_EXCLUDEDSPECIALCHARS = "[]{}";
    // Error messages
    public static final String FAILED_TO_CREATE_USER_WITH_USERNAME = "Failed to create user with username: {}";
    public static final String USER_ALREADY_EXISTS_PLEASE_TRY_AGAIN = "The user already exists. Please try again "
            + "with a different email.";
    public static final String UNEXPECTED_ERROR = "An unexpected error occurred. Please try again later.";
    public static final String ADD_REQ_PAR = "Please add all required fields.";
    public static final String INVALID_PASSWORD = "Your password does not meet the security requirements. "
            + "Ensure it complies with all password policies.";
    public static final String RECORD_ALREADY_EXISTS_ERROR_MESSAGE = "RecordAlreadyExistsException ";

    // redirect endpoints or literals
    public static final String REDIRECT_LITERAL = "redirect:/";
    public static final String RECOVERY_FORGOT_PASSWORD = "recovery/forgot-password";
    public static final String RECOVERY_CHANGE_PASSWORD = "recovery/change-password";
    public static final String RECOVERY_INV_SECRET = "recovery/invalid-secret-provided";
    public static final String RECOVERY_PASSWORD_CHANGED = "recovery/password-changed";
    public static final String RECOVERY_EMAIL_SENT = "recovery/email-sent";
    public static final String SELF_SIGN_UP = "sign-up";
    public static final String USER_CREATED = "user-created";
    public static final String TERMS_OF_USE = "terms-of-use";
    public static final String PRIVACY_AGREEMENT = "privacy-agreement";
    public static final String UNABLE_TO_FETCH_PASSWORD_POLICY = "Unable to fetch password policy";
    public static final String USER_CREATED_SUCCESSFULLY = "User has been created successfully.";
    public static final String EMAIL_SENT_PREFIX = "An email was sent to:\n";
    public static final String EMAIL_SENT_SUFFIX = "Please check your email and verify your account.";

    public static final String SIGN_UP_NOT_ENABLED = "Sign up not enabled";    
    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    public static final String SCOPE = "scope";
    public static final String CLIENT_ID = "client_id";
}
