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

package org.eclipse.ecsp.oauth2.server.core.authentication.converters;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Authentication converter that extracts public client credentials from refresh token requests.
 * This converter handles the case where a public client (using PKCE) sends a refresh_token
 * request with only client_id (no client_secret).
 *
 * <p>Request format expected:
 * <pre>
 * POST /oauth2/token
 * Content-Type: application/x-www-form-urlencoded
 *
 * grant_type=refresh_token&amp;client_id=marketplace_client&amp;refresh_token=xxx
 * </pre>
 *
 * <p>This converter only activates when:
 * <ul>
 *   <li>grant_type is "refresh_token"</li>
 *   <li>client_id is present in the request</li>
 *   <li>client_secret is NOT present in the request</li>
 *   <li>No Authorization header with Basic credentials is present</li>
 * </ul>
 */
public class PublicClientRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    private static final int BASIC_SCHEME_PREFIX_LENGTH = 6; // length of "Basic "

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        // Only handle refresh_token requests
        if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
            return null;
        }

        // Only handle when no client_secret is provided (public client)
        String clientSecret = request.getParameter(OAuth2ParameterNames.CLIENT_SECRET);
        if (StringUtils.hasText(clientSecret)) {
            return null;
        }

        // Only handle when no Basic auth header is present.
        // Use HttpHeaders.AUTHORIZATION constant and case-insensitive scheme check per RFC 7235.
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(authorizationHeader)
                && authorizationHeader.regionMatches(true, 0, "Basic ", 0, BASIC_SCHEME_PREFIX_LENGTH)) {
            return null;
        }

        // client_id is required
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }

        // Pass additional parameters for downstream validation
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(OAuth2ParameterNames.GRANT_TYPE, grantType);

        String refreshToken = request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN);
        if (StringUtils.hasText(refreshToken)) {
            additionalParameters.put(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken);
        }

        return new OAuth2ClientAuthenticationToken(clientId,
                ClientAuthenticationMethod.NONE, null, additionalParameters);
    }
}
