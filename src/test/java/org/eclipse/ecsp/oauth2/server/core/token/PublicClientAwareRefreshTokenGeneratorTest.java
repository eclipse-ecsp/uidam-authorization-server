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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PublicClientAwareRefreshTokenGenerator}.
 */
class PublicClientAwareRefreshTokenGeneratorTest {

    private static final int TTL_MINUTES_30 = 30;
    private static final int TTL_HOURS_1 = 1;

    private PublicClientAwareRefreshTokenGenerator generator;

    @BeforeEach
    void setUp() {
        generator = new PublicClientAwareRefreshTokenGenerator();
    }

    @Test
    void generate_returnsNull_whenTokenTypeIsNotRefreshToken() {
        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);

        OAuth2RefreshToken result = generator.generate(context);

        assertNull(result, "Should return null for non-refresh-token type");
    }

    @Test
    void generate_returnsRefreshToken_whenTokenTypeIsRefreshToken() {
        TokenSettings tokenSettings = TokenSettings.builder()
                .refreshTokenTimeToLive(Duration.ofHours(TTL_HOURS_1))
                .build();
        RegisteredClient registeredClient = RegisteredClient.withId("test-id")
                .clientId("test-client")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(tokenSettings)
                .build();

        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.REFRESH_TOKEN);
        when(context.getRegisteredClient()).thenReturn(registeredClient);

        OAuth2RefreshToken result = generator.generate(context);

        assertNotNull(result, "Should generate a refresh token");
        assertNotNull(result.getTokenValue(), "Token value should not be null");
        assertNotNull(result.getIssuedAt(), "Issued-at should not be null");
        assertNotNull(result.getExpiresAt(), "Expires-at should not be null");
    }

    @Test
    void generate_tokenExpiryMatchesTtlSetting() {
        Duration ttl = Duration.ofMinutes(TTL_MINUTES_30);
        TokenSettings tokenSettings = TokenSettings.builder()
                .refreshTokenTimeToLive(ttl)
                .build();
        RegisteredClient registeredClient = RegisteredClient.withId("test-id")
                .clientId("test-client")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(tokenSettings)
                .build();

        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.REFRESH_TOKEN);
        when(context.getRegisteredClient()).thenReturn(registeredClient);

        OAuth2RefreshToken result = generator.generate(context);

        assertNotNull(result);
        Duration actualTtl = Duration.between(result.getIssuedAt(), result.getExpiresAt());
        assertTrue(actualTtl.toSeconds() >= ttl.toSeconds() - 1
                && actualTtl.toSeconds() <= ttl.toSeconds() + 1,
                "TTL should match configured refresh token time-to-live");
    }

    @Test
    void generate_tokenValueIsBase64UrlEncoded() {
        TokenSettings tokenSettings = TokenSettings.builder()
                .refreshTokenTimeToLive(Duration.ofHours(TTL_HOURS_1))
                .build();
        RegisteredClient registeredClient = RegisteredClient.withId("test-id")
                .clientId("test-client")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(tokenSettings)
                .build();

        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.REFRESH_TOKEN);
        when(context.getRegisteredClient()).thenReturn(registeredClient);

        OAuth2RefreshToken result = generator.generate(context);

        assertNotNull(result);
        // Base64URL tokens must not contain '+', '/', or '='
        String tokenValue = result.getTokenValue();
        assertFalse(tokenValue.contains("+"), "Token must not contain '+'");
        assertFalse(tokenValue.contains("/"), "Token must not contain '/'");
        assertFalse(tokenValue.contains("="), "Token must not contain '=' (no padding)");
    }

    @Test
    void generate_eachCallProducesUniqueToken() {
        TokenSettings tokenSettings = TokenSettings.builder()
                .refreshTokenTimeToLive(Duration.ofHours(TTL_HOURS_1))
                .build();
        RegisteredClient registeredClient = RegisteredClient.withId("test-id")
                .clientId("test-client")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(tokenSettings)
                .build();

        OAuth2TokenContext context = mock(OAuth2TokenContext.class);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.REFRESH_TOKEN);
        when(context.getRegisteredClient()).thenReturn(registeredClient);

        OAuth2RefreshToken token1 = generator.generate(context);
        OAuth2RefreshToken token2 = generator.generate(context);

        assertNotNull(token1);
        assertNotNull(token2);
        assertNotEquals(token1.getTokenValue(), token2.getTokenValue(),
                "Each generated token should be unique");
    }
}
