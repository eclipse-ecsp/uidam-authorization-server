/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p>Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

/**
 * Creates {@link CustomWebAuthenticationDetails} instances from HTTP requests.
 *
 * <p>This source is responsible for building authentication details that include
 * additional browser and client information beyond the standard IP address and session ID.
 *
 * <p>Usage: Configure this as the authentication details source in your security configuration
 * for form login, OAuth2 login, or any other authentication mechanism.
 *
 * <p>Example configuration:
 * <pre>
 * http.formLogin(form -> form
 *     .authenticationDetailsSource(customWebAuthenticationDetailsSource)
 * );
 * </pre>
 *
 * @author UIDAM Team
 * @since 1.0
 * @see CustomWebAuthenticationDetails
 */
@Component
public class CustomWebAuthenticationDetailsSource 
        implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {

    /**
     * Builds custom authentication details from the HTTP request.
     *
     * @param request the HTTP request from which to extract authentication details
     * @return a new {@link CustomWebAuthenticationDetails} instance containing
     *         remote address, session ID, user agent, and other HTTP headers
     */
    @Override
    public CustomWebAuthenticationDetails buildDetails(HttpServletRequest request) {
        return new CustomWebAuthenticationDetails(request);
    }
}
