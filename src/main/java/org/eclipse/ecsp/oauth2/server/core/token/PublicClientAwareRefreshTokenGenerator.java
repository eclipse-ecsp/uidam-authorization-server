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

package org.eclipse.ecsp.oauth2.server.core.token;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.Base64;

/**
 * Custom refresh token generator that issues refresh tokens for both confidential
 * and public (PKCE) clients.
 *
 * <p>Spring Security's default {@code OAuth2RefreshTokenGenerator} explicitly skips
 * refresh token generation for public clients using {@code ClientAuthenticationMethod.NONE}.
 * This implementation removes that restriction so that PKCE clients with the
 * {@code refresh_token} authorization grant type receive a refresh token alongside
 * the access token during the authorization-code token exchange.
 */
public class PublicClientAwareRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private final StringKeyGenerator refreshTokenGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        // Allow refresh tokens for all clients, including public/PKCE clients.
        // Rotation is enforced via TokenSettings.reuseRefreshTokens=false in RegisteredClientMapper.
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(
                context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
        return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
    }
}
