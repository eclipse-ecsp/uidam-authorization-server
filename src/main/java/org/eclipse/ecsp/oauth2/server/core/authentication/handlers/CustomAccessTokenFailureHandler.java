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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static org.eclipse.ecsp.oauth2.server.core.utils.CustomOauth2ErrorMessage.setCustomErrorMessage;

/**
 * The CustomAccessTokenFailureHandler class implements the AuthenticationFailureHandler interface.
 * This class is used to handle authentication failure events in a Spring Security context.
 */
@Component
public class CustomAccessTokenFailureHandler implements AuthenticationFailureHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomAccessTokenFailureHandler.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * This method is an override of the onAuthenticationFailure method in the AuthenticationFailureHandler interface.
     * It is called when a user's authentication attempt has failed.
     * The method registers a new JavaTimeModule to the ObjectMapper, and retrieves the failed
     * OAuth2AuthenticationException.
     * If the OAuth2AuthenticationException is not null, it sets a custom error message to the response and writes the
     * response as a JSON string.
     *
     * @param request the HttpServletRequest associated with the authentication event
     * @param response the HttpServletResponse associated with the authentication event
     * @param exception the AuthenticationException object containing the details of the authentication failure
     * @throws IOException if an input or output exception occurred
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        LOGGER.debug("## onAuthenticationFailure - START");
        objectMapper.registerModule(new JavaTimeModule());
        LOGGER.error("Authentication failure occurred with", exception);
        OAuth2AuthenticationException oauth2AuthenticationException = (OAuth2AuthenticationException) exception;
        CustomOauth2ErrorResponse customOauth2ErrorResponse;
        if (null != oauth2AuthenticationException) {
            customOauth2ErrorResponse = setCustomErrorMessage(oauth2AuthenticationException, response);
            response.getOutputStream().println(objectMapper.writeValueAsString(customOauth2ErrorResponse));
            LOGGER.debug("## onAuthenticationFailure - END");
        }
    }

}