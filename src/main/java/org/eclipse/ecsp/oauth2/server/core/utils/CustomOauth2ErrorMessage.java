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

import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2ErrorResponse;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.time.LocalDateTime;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.USER_NOT_FOUND;

/**
 * The CustomOauth2ErrorMessage class is a utility class used to generate custom error messages for OAuth2
 * authentication exceptions.
 */
public class CustomOauth2ErrorMessage {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomOauth2ErrorMessage.class);

    protected CustomOauth2ErrorMessage() {
        // Prevent instantiation
    }

    /**
     * This method generates a custom error message for an OAuth2AuthenticationException.
     * It checks the error code of the exception and generates a custom error message based on it.
     * If the error code is INVALID_REQUEST and the error description contains CLIENT_ID or REDIRECT_URI, it generates a
     * custom error message with the corresponding error code.
     * If the exception is null, it generates a custom error message with the INVALID_REQUEST error code.
     *
     * @param oauth2AuthenticationException the OAuth2AuthenticationException for which to generate a custom error
     *                                      message.
     * @param response the HttpServletResponse to which to set the status.
     * @return a CustomOauth2ErrorResponse containing the custom error message.
     */
    public static CustomOauth2ErrorResponse setCustomErrorMessage(OAuth2AuthenticationException
                                                                          oauth2AuthenticationException,
                                                                  HttpServletResponse response) {
        if (oauth2AuthenticationException != null) {
            if (OAuth2ErrorCodes.INVALID_REQUEST.equals(oauth2AuthenticationException.getError().getErrorCode())) {
                String description = oauth2AuthenticationException.getError().getDescription();
                if (description != null && description.contains(OAuth2ParameterNames.CLIENT_ID)) {
                    return setCustomErrorResponse(response, CustomOauth2TokenGenErrorCodes.INVALID_CLIENT, null);
                } else if (description != null && description.contains(OAuth2ParameterNames.REDIRECT_URI)) {
                    return setCustomErrorResponse(response, CustomOauth2TokenGenErrorCodes.INVALID_REDIRECT_URI, null);
                }
            }
            return setCustomErrorResponse(response, CustomOauth2TokenGenErrorCodes
                            .getOauthErrorMapping(oauth2AuthenticationException.getError().getErrorCode()),
                    oauth2AuthenticationException.getError().getDescription());
        } else {
            return setCustomErrorResponse(response, CustomOauth2TokenGenErrorCodes.INVALID_REQUEST, null);
        }
    }

    /**
     * This method generates a custom error response with the provided error code and description.
     * It sets the status of the response to the status of the error code.
     * If the error code is USER_NOT_FOUND, it sets the error description to the provided custom error description.
     * Otherwise, it sets the error description to the description of the error code.
     * It returns a CustomOauth2ErrorResponse containing the error code, error description, and current timestamp.
     *
     * @param response the HttpServletResponse to which to set the status.
     * @param oauth2ErrorMapping the error code for the custom error response.
     * @param customErrorDescription the custom error description for the custom error response.
     * @return a CustomOauth2ErrorResponse containing the custom error response.
     */
    private static CustomOauth2ErrorResponse setCustomErrorResponse(HttpServletResponse response,
                                                                    CustomOauth2TokenGenErrorCodes oauth2ErrorMapping,
                                                                    String customErrorDescription) {
        response.setStatus(oauth2ErrorMapping.getStatus());
        String errorDescription;
        if (USER_NOT_FOUND.equals(oauth2ErrorMapping.name())) {
            errorDescription = customErrorDescription;
        } else {
            errorDescription = oauth2ErrorMapping.getDescription();
        }
        LOGGER.error("## onAuthenticationFailure - {}", errorDescription);
        return CustomOauth2ErrorResponse.builder().error(oauth2ErrorMapping.name())
                .errorCode(oauth2ErrorMapping.getCode()).errorDescription(errorDescription)
                .timestamp(LocalDateTime.now().toString()).build();
    }

}