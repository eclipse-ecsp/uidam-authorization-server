/*******************************************************************************
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
 ******************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.authentication.converters;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Unit tests for {@link PublicClientRefreshTokenAuthenticationConverter}.
 */
class PublicClientRefreshTokenAuthenticationConverterTest {

    private PublicClientRefreshTokenAuthenticationConverter converter;

    @BeforeEach
    void setUp() {
        converter = new PublicClientRefreshTokenAuthenticationConverter();
    }

    private MockHttpServletRequest buildRequest(String grantType, String clientId,
                                                String clientSecret, String refreshToken,
                                                String authHeader) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (grantType != null) {
            request.setParameter(OAuth2ParameterNames.GRANT_TYPE, grantType);
        }
        if (clientId != null) {
            request.setParameter(OAuth2ParameterNames.CLIENT_ID, clientId);
        }
        if (clientSecret != null) {
            request.setParameter(OAuth2ParameterNames.CLIENT_SECRET, clientSecret);
        }
        if (refreshToken != null) {
            request.setParameter(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken);
        }
        if (authHeader != null) {
            request.addHeader("Authorization", authHeader);
        }
        return request;
    }

    @Test
    void convert_returnsNull_whenGrantTypeIsNotRefreshToken() {
        MockHttpServletRequest request = buildRequest(
                "client_credentials", "my-client", null, null, null);

        Authentication result = converter.convert(request);

        assertNull(result, "Should return null for non-refresh-token grant type");
    }

    @Test
    void convert_returnsNull_whenGrantTypeIsMissing() {
        MockHttpServletRequest request = buildRequest(null, "my-client", null, null, null);

        Authentication result = converter.convert(request);

        assertNull(result, "Should return null when grant_type is absent");
    }

    @Test
    void convert_returnsNull_whenClientSecretIsPresent() {
        MockHttpServletRequest request = buildRequest(
                "refresh_token", "my-client", "super-secret", "some-token", null);

        Authentication result = converter.convert(request);

        assertNull(result, "Should return null when client_secret is provided (confidential client)");
    }

    @Test
    void convert_returnsNull_whenBasicAuthHeaderPresent() {
        MockHttpServletRequest request = buildRequest(
                "refresh_token", "my-client", null, "some-token", "Basic dXNlcjpwYXNz");

        Authentication result = converter.convert(request);

        assertNull(result, "Should return null when Basic Authorization header is present");
    }

    @Test
    void convert_returnsNull_whenBasicAuthHeaderPresentCaseInsensitive() {
        // RFC 7235 requires case-insensitive scheme detection
        MockHttpServletRequest request = buildRequest(
                "refresh_token", "my-client", null, "some-token", "BASIC dXNlcjpwYXNz");

        Authentication result = converter.convert(request);

        assertNull(result, "Should return null when Basic auth header is present regardless of case");
    }

    @Test
    void convert_returnsNull_whenClientIdIsAbsent() {
        MockHttpServletRequest request = buildRequest(
                "refresh_token", null, null, "some-token", null);

        Authentication result = converter.convert(request);

        assertNull(result, "Should return null when client_id is missing");
    }

    @Test
    void convert_returnsToken_whenAllConditionsMet() {
        MockHttpServletRequest request = buildRequest(
                "refresh_token", "test-portal", null, "refresh-token-abc", null);

        Authentication result = converter.convert(request);

        assertNotNull(result, "Should produce an authentication token for public client");
        OAuth2ClientAuthenticationToken token = (OAuth2ClientAuthenticationToken) result;
        assertEquals("test-portal", token.getPrincipal(),
                "Principal should be the client_id");
        assertEquals(ClientAuthenticationMethod.NONE, token.getClientAuthenticationMethod(),
                "Authentication method should be NONE for public clients");
    }

    @Test
    void convert_includesRefreshTokenInAdditionalParams() {
        MockHttpServletRequest request = buildRequest(
                "refresh_token", "test-portal", null, "refresh-token-abc", null);

        OAuth2ClientAuthenticationToken token =
                (OAuth2ClientAuthenticationToken) converter.convert(request);

        assertNotNull(token);
        assertEquals("refresh-token-abc",
                token.getAdditionalParameters().get(OAuth2ParameterNames.REFRESH_TOKEN),
                "refresh_token value should be present in additional parameters");
    }

    @Test
    void convert_doesNotIncludeRefreshTokenParam_whenAbsent() {
        MockHttpServletRequest request = buildRequest(
                "refresh_token", "test-portal", null, null, null);

        OAuth2ClientAuthenticationToken token =
                (OAuth2ClientAuthenticationToken) converter.convert(request);

        assertNotNull(token);
        assertNull(token.getAdditionalParameters().get(OAuth2ParameterNames.REFRESH_TOKEN),
                "refresh_token should not be in params when not provided in request");
    }

    @Test
    void convert_includesGrantTypeInAdditionalParams() {
        MockHttpServletRequest request = buildRequest(
                "refresh_token", "test-portal", null, "token-xyz", null);

        OAuth2ClientAuthenticationToken token =
                (OAuth2ClientAuthenticationToken) converter.convert(request);

        assertNotNull(token);
        assertEquals("refresh_token",
                token.getAdditionalParameters().get(OAuth2ParameterNames.GRANT_TYPE),
                "grant_type should be propagated in additional parameters");
    }

    @Test
    void convert_allowsBearerAuthHeader_asNotBasic() {
        // Bearer token header is not Basic — converter should proceed normally
        MockHttpServletRequest request = buildRequest(
                "refresh_token", "test-portal", null, "refresh-token-abc",
                "Bearer some.jwt.token");

        Authentication result = converter.convert(request);

        assertNotNull(result, "Should produce a token when Authorization is Bearer (not Basic)");
    }
}
