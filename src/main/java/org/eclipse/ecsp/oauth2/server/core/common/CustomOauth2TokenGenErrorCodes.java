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

package org.eclipse.ecsp.oauth2.server.core.common;

import lombok.Getter;
import org.eclipse.ecsp.oauth2.server.core.utils.EnumUtils;

/**
 * CustomOauth2TokenGenErrorCodes is an enumeration that defines custom error codes for token generation in OAuth2.
 */
@Getter
public enum CustomOauth2TokenGenErrorCodes {
    INVALID_SCOPE("TG-001", "Requested Scope Is Invalid", 400),
    INVALID_CLIENT("TG-002", "Request Client Is Invalid", 401),
    INVALID_REQUEST("TG-003", "Request is invalid", 400),
    UNAUTHORIZED_CLIENT("TG-004", "Client is Unauthorized", 401),
    ACCESS_DENIED("TG-005", "Access Denied", 400),
    UNSUPPORTED_RESPONSE_TYPE("TG-006", "Response Type is not supported", 403),

    INSUFFICIENT_SCOPE("TG-007", "Scope is Insufficient", 403),
    INVALID_TOKEN("TG-008", "Token is invalid", 401),
    SERVER_ERROR("TG-009", "Internal Server Error", 500),
    TEMPORARILY_UNAVAILABLE("TG-010", "Service Temporarily Unavailable", 503),

    INVALID_GRANT("TG-011", "Authorization code or refresh token is invalid,  expired,  revoked,"
            + " does not match the redirection URI used in the authorization request", 400),
    UNSUPPORTED_GRANT_TYPE("TG-012", "Grant Type is not supported", 400),
    UNSUPPORTED_TOKEN_TYPE("TG-013", "Token Type is not supported", 400),
    INVALID_REDIRECT_URI("TG-014", "Redirect URI is invalid", 400),
    MISSING_FIELD_IN_REQUEST_BODY("TG-015", "User/Client id is missing in request body!", 400),
    USER_NOT_FOUND("TG-016", "User not found", 404),
    USER_NOT_ACTIVE("TG-020", "User is not active", 403),
    ACCOUNT_NOT_FOUND("TG-021", "Account not found or user not associated with account", 403),
    RECORD_ALREADY_EXISTS("TG-017", "Record already exists", 409),
    RESOURCE_NOT_FOUND("TG-018", "Resource not found", 404),
    BAD_REQUEST("TG-019", "Bad Request", 400);

    private final String code;
    private final String description;

    private final int status;

    /**
     * Constructor for the enum values.
     *
     * @param code the error code
     * @param description the description of the error
     * @param status the HTTP status associated with the error
     */
    CustomOauth2TokenGenErrorCodes(String code, String description, int status) {
        this.code = code;
        this.description = description;
        this.status = status;
    }

    /**
     * This static method maps a string value to a corresponding CustomOauth2TokenGenErrorCodes enum value.
     * If the string value does not match any enum value, it returns INVALID_REQUEST.
     *
     * @param value the string value to be converted to an enum value
     * @return the corresponding CustomOauth2TokenGenErrorCodes enum value, or INVALID_REQUEST if the string value does
     *         not match any enum value
     */
    public static CustomOauth2TokenGenErrorCodes getOauthErrorMapping(String value) {
        return EnumUtils.findFromValueCaseInsensitive(CustomOauth2TokenGenErrorCodes.class,
                CustomOauth2TokenGenErrorCodes::name, value).orElse(CustomOauth2TokenGenErrorCodes.INVALID_REQUEST);
    }
}
