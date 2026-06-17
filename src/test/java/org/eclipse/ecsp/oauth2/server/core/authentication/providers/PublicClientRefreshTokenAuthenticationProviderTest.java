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

package org.eclipse.ecsp.oauth2.server.core.authentication.providers;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ClientProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PublicClientRefreshTokenAuthenticationProvider}.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PublicClientRefreshTokenAuthenticationProviderTest {

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private OAuth2AuthorizationService authorizationService;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    private PublicClientRefreshTokenAuthenticationProvider provider;

    private static final String CLIENT_ID = "test-portal";
    private static final String REGISTERED_CLIENT_DB_ID = "db-id-001";
    private static final String REFRESH_TOKEN_VALUE = "some-refresh-token-value";

    @BeforeEach
    void setUp() {
        provider = new PublicClientRefreshTokenAuthenticationProvider(
                registeredClientRepository, authorizationService, tenantConfigurationService);
    }

    // --- Constructor null-checks ---

    @Test
    void constructor_throwsOnNullRepository() {
        assertThrows(IllegalArgumentException.class, () ->
                new PublicClientRefreshTokenAuthenticationProvider(
                        null, authorizationService, tenantConfigurationService));
    }

    @Test
    void constructor_throwsOnNullAuthorizationService() {
        assertThrows(IllegalArgumentException.class, () ->
                new PublicClientRefreshTokenAuthenticationProvider(
                        registeredClientRepository, null, tenantConfigurationService));
    }

    @Test
    void constructor_throwsOnNullTenantConfigService() {
        assertThrows(IllegalArgumentException.class, () ->
                new PublicClientRefreshTokenAuthenticationProvider(
                        registeredClientRepository, authorizationService, null));
    }

    // --- supports() ---

    @Test
    void supports_returnsTrue_forClientAuthToken() {
        assertTrue(provider.supports(OAuth2ClientAuthenticationToken.class));
    }

    // --- Grant type filtering ---

    @Test
    void authenticate_returnsNull_whenGrantTypeIsNotRefreshToken() {
        OAuth2ClientAuthenticationToken token = buildToken(CLIENT_ID, "authorization_code", null);

        Authentication result = provider.authenticate(token);

        assertNull(result, "Should return null for non-refresh-token grant types");
    }

    @Test
    void authenticate_returnsNull_whenAdditionalParamsAreNull() {
        OAuth2ClientAuthenticationToken token = mock(OAuth2ClientAuthenticationToken.class);
        when(token.getAdditionalParameters()).thenReturn(null);

        Authentication result = provider.authenticate(token);

        assertNull(result, "Should return null when additional parameters are null");
    }

    // --- Tenant feature flag ---

    @Test
    void authenticate_returnsNull_whenTenantDisablesPublicClientRefreshToken() {
        mockTenantWithRefreshEnabled(false);
        OAuth2ClientAuthenticationToken token = buildToken(CLIENT_ID, "refresh_token", REFRESH_TOKEN_VALUE);

        Authentication result = provider.authenticate(token);

        assertNull(result, "Should return null when feature is disabled at tenant level");
    }

    @Test
    void authenticate_proceeds_whenTenantPropertyIsNull() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(null);
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildPublicRegisteredClient(true));

        OAuth2ClientAuthenticationToken token = buildToken(CLIENT_ID, "refresh_token", REFRESH_TOKEN_VALUE);
        mockAuthorizationForRefreshToken(REFRESH_TOKEN_VALUE, REGISTERED_CLIENT_DB_ID);

        Authentication result = provider.authenticate(token);

        assertNotNull(result);
    }

    // --- Principal null-safety ---

    @Test
    void authenticate_throws_whenPrincipalIsNull() {
        mockTenantWithRefreshEnabled(true);
        OAuth2ClientAuthenticationToken token = mock(OAuth2ClientAuthenticationToken.class);
        Map<String, Object> params = new HashMap<>();
        params.put(OAuth2ParameterNames.GRANT_TYPE, "refresh_token");
        when(token.getAdditionalParameters()).thenReturn(params);
        when(token.getPrincipal()).thenReturn(null);

        assertThrows(OAuth2AuthenticationException.class,
                () -> provider.authenticate(token),
                "Should throw when principal (client_id) is null");
    }

    // --- Client lookup ---

    @Test
    void authenticate_throws_whenClientNotFound() {
        mockTenantWithRefreshEnabled(true);
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(null);

        OAuth2ClientAuthenticationToken token = buildToken(CLIENT_ID, "refresh_token", REFRESH_TOKEN_VALUE);

        assertThrows(OAuth2AuthenticationException.class,
                () -> provider.authenticate(token),
                "Should throw when client is not found in repository");
    }

    // --- Not a public client ---

    @Test
    void authenticate_returnsNull_whenClientIsNotPublic() {
        mockTenantWithRefreshEnabled(true);
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildPublicRegisteredClient(false)); // confidential client

        OAuth2ClientAuthenticationToken token = buildToken(CLIENT_ID, "refresh_token", REFRESH_TOKEN_VALUE);

        Authentication result = provider.authenticate(token);

        assertNull(result, "Should return null for confidential clients (not NONE auth method)");
    }

    // --- Grant type authorization check ---

    @Test
    void authenticate_throws_whenRefreshTokenGrantTypeNotAllowed() {
        mockTenantWithRefreshEnabled(true);
        RegisteredClient clientWithoutRefreshGrant = RegisteredClient.withId(REGISTERED_CLIENT_DB_ID)
                .clientId(CLIENT_ID)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost/callback")
                .tokenSettings(TokenSettings.builder()
                        .refreshTokenTimeToLive(Duration.ofHours(1))
                        .build())
                .build();
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(clientWithoutRefreshGrant);

        OAuth2ClientAuthenticationToken token = buildToken(CLIENT_ID, "refresh_token", REFRESH_TOKEN_VALUE);

        assertThrows(OAuth2AuthenticationException.class,
                () -> provider.authenticate(token),
                "Should throw when refresh_token grant is not in client's authorized grant types");
    }

    // --- Refresh token binding check ---

    @Test
    void authenticate_throws_whenRefreshTokenBelongsToDifferentClient() {
        mockTenantWithRefreshEnabled(true);
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildPublicRegisteredClient(true));

        // Simulate token belonging to a different client
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getRegisteredClientId()).thenReturn("other-client-db-id");
        when(authorizationService.findByToken(eq(REFRESH_TOKEN_VALUE),
                any(OAuth2TokenType.class)))
                .thenReturn(authorization);

        OAuth2ClientAuthenticationToken token = buildToken(CLIENT_ID, "refresh_token", REFRESH_TOKEN_VALUE);

        assertThrows(OAuth2AuthenticationException.class,
                () -> provider.authenticate(token),
                "Should throw when refresh token is bound to a different client");
    }

    @Test
    void authenticate_succeeds_whenRefreshTokenBelongsToCorrectClient() {
        mockTenantWithRefreshEnabled(true);
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildPublicRegisteredClient(true));
        mockAuthorizationForRefreshToken(REFRESH_TOKEN_VALUE, REGISTERED_CLIENT_DB_ID);

        OAuth2ClientAuthenticationToken token = buildToken(CLIENT_ID, "refresh_token", REFRESH_TOKEN_VALUE);

        Authentication result = provider.authenticate(token);

        assertNotNull(result);
        assertInstanceOf(OAuth2ClientAuthenticationToken.class, result);
        OAuth2ClientAuthenticationToken authToken = (OAuth2ClientAuthenticationToken) result;
        assertNotNull(authToken.getRegisteredClient());
        assertEquals(CLIENT_ID, authToken.getRegisteredClient().getClientId());
    }

    @Test
    void authenticate_succeeds_whenNoRefreshTokenValueInRequest() {
        // refresh_token param missing — token binding check is skipped
        mockTenantWithRefreshEnabled(true);
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildPublicRegisteredClient(true));

        Map<String, Object> params = new HashMap<>();
        params.put(OAuth2ParameterNames.GRANT_TYPE, "refresh_token");
        // no refresh_token param
        OAuth2ClientAuthenticationToken token = mock(OAuth2ClientAuthenticationToken.class);
        when(token.getAdditionalParameters()).thenReturn(params);
        when(token.getPrincipal()).thenReturn(CLIENT_ID);
        when(token.getDetails()).thenReturn(null);

        Authentication result = provider.authenticate(token);

        assertNotNull(result, "Should succeed even when refresh_token value not provided");
    }

    @Test
    void authenticate_succeeds_whenAuthorizationNotFoundForToken() {
        // Token value provided but authorizationService returns null — should pass (server may have reissued)
        mockTenantWithRefreshEnabled(true);
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildPublicRegisteredClient(true));
        when(authorizationService.findByToken(eq(REFRESH_TOKEN_VALUE),
                any(OAuth2TokenType.class)))
                .thenReturn(null);

        OAuth2ClientAuthenticationToken token = buildToken(CLIENT_ID, "refresh_token", REFRESH_TOKEN_VALUE);

        Authentication result = provider.authenticate(token);

        assertNotNull(result, "Should succeed when authorization record is not found (let token endpoint handle it)");
    }

    // --- Authentication method on result ---

    @Test
    void authenticate_resultHasNoneAuthenticationMethod() {
        mockTenantWithRefreshEnabled(true);
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(buildPublicRegisteredClient(true));
        mockAuthorizationForRefreshToken(REFRESH_TOKEN_VALUE, REGISTERED_CLIENT_DB_ID);

        OAuth2ClientAuthenticationToken token = buildToken(CLIENT_ID, "refresh_token", REFRESH_TOKEN_VALUE);

        OAuth2ClientAuthenticationToken result =
                (OAuth2ClientAuthenticationToken) provider.authenticate(token);

        assertEquals(ClientAuthenticationMethod.NONE, result.getClientAuthenticationMethod());
    }

    // --- Helpers ---

    private OAuth2ClientAuthenticationToken buildToken(String clientId, String grantType,
                                                       String refreshToken) {
        Map<String, Object> params = new HashMap<>();
        params.put(OAuth2ParameterNames.GRANT_TYPE, grantType);
        if (refreshToken != null) {
            params.put(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken);
        }
        OAuth2ClientAuthenticationToken token = mock(OAuth2ClientAuthenticationToken.class);
        when(token.getAdditionalParameters()).thenReturn(params);
        when(token.getPrincipal()).thenReturn(clientId);
        when(token.getDetails()).thenReturn(null);
        return token;
    }

    private RegisteredClient buildPublicRegisteredClient(boolean includeNoneMethod) {
        RegisteredClient.Builder builder = RegisteredClient.withId(REGISTERED_CLIENT_DB_ID)
                .clientId(CLIENT_ID)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost/callback")
                .tokenSettings(TokenSettings.builder()
                        .refreshTokenTimeToLive(Duration.ofHours(1))
                        .build());
        if (includeNoneMethod) {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        }
        return builder.build();
    }

    private void mockTenantWithRefreshEnabled(boolean enabled) {
        ClientProperties clientProperties = mock(ClientProperties.class);
        when(clientProperties.getPublicClientRefreshTokenEnabled()).thenReturn(enabled);
        TenantProperties tenantProperties = mock(TenantProperties.class);
        when(tenantProperties.getClient()).thenReturn(clientProperties);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
    }

    private void mockAuthorizationForRefreshToken(String tokenValue, String registeredClientId) {
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(authorization.getRegisteredClientId()).thenReturn(registeredClientId);
        when(authorizationService.findByToken(eq(tokenValue), any(OAuth2TokenType.class)))
                .thenReturn(authorization);
    }
}
