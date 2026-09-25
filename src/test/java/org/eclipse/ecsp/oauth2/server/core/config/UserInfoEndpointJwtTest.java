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

package org.eclipse.ecsp.oauth2.server.core.config;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcUserInfoEndpointFilter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Reproduces issue 1285 through real bearer authentication and OIDC UserInfo filters.
 * Only the authorization store is in memory; JWT decoding, signatures and endpoint validation are real.
 */
class UserInfoEndpointJwtTest {

    private static final int RSA_BITS = 2048;
    private static final long TOKEN_LIFETIME_SECONDS = 3600;
    private static final long OUTSIDE_CLOCK_SKEW_SECONDS = 120;
    private static final String SUBJECT = "userinfo-test-user";
    private static final String ACCESS_TOKEN_TYPE = IgniteOauth2CoreConstants.CLAIM_HEADER_JWT_ACCESS_TOKEN_TYPE;
    private static final String ID_TOKEN_TYPE = IgniteOauth2CoreConstants.CLAIM_HEADER_ID_TOKEN_TYPE;
    private static final Set<String> SCOPES = Set.of(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL);
    private static final String USERINFO_ENDPOINT = "/oauth2/userinfo";

    private RSAKey signingKey;
    private JWKSource<SecurityContext> jwkSource;
    private JwtDecoder fixedDecoder;
    private InMemoryOAuth2AuthorizationService authorizations;
    private RegisteredClient client;
    private Instant now;

    @BeforeEach
    void setUp() throws Exception {
        signingKey = new RSAKeyGenerator(RSA_BITS).keyID("userinfo-signing-key").generate();
        jwkSource = new ImmutableJWKSet<>(new JWKSet(signingKey.toPublicJWK()));
        fixedDecoder = new AuthorizationServerConfig(mock(TenantConfigurationService.class)).jwtDecoder(jwkSource);
        authorizations = new InMemoryOAuth2AuthorizationService();
        client = RegisteredClient.withId("userinfo-client")
                .clientId("userinfo-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://client.example/callback")
                .scopes(scopes -> scopes.addAll(SCOPES))
                .build();
        now = Instant.now();
    }

    @Test
    void sameIssuedAccessTokenFailsBeforeFixAndReturnsUserInfoAfterFix() throws Exception {
        String accessToken = validToken(ACCESS_TOKEN_TYPE);
        saveAuthorization(accessToken, SCOPES, false, true);
        JwtDecoder originalDecoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);

        userInfo(originalDecoder, accessToken)
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")))
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("typ")));

        userInfo(fixedDecoder, accessToken)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value(SUBJECT))
                .andExpect(jsonPath("$.name").value("UserInfo Test User"))
                .andExpect(jsonPath("$.email").value("userinfo@example.com"));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"JWT", "at+jwt", "application/at+jwt"})
    void acceptsSupportedTypesForStoredAccessTokens(String type) throws Exception {
        String token = validToken(type);
        saveAuthorization(token, SCOPES, false, true);
        userInfo(fixedDecoder, token).andExpect(status().isOk()).andExpect(jsonPath("$.sub").value(SUBJECT));
    }

    @ParameterizedTest
    @ValueSource(strings = {"id+jwt", "unexpected-type"})
    void rejectsUnrelatedTypesEvenWhenStoredAsAccessToken(String type) throws Exception {
        String token = validToken(type);
        saveAuthorization(token, SCOPES, false, true);
        assertInvalidToken(token);
    }

    @Test
    void rejectsExpiredAccessToken() throws Exception {
        String token = signToken(ACCESS_TOKEN_TYPE, signingKey, now.minusSeconds(TOKEN_LIFETIME_SECONDS),
                now.minusSeconds(OUTSIDE_CLOCK_SKEW_SECONDS), null);
        saveAuthorization(token, SCOPES, false, true);
        assertInvalidToken(token);
    }

    @Test
    void rejectsAccessTokenNotYetValid() throws Exception {
        String token = signToken(ACCESS_TOKEN_TYPE, signingKey, now,
                now.plusSeconds(TOKEN_LIFETIME_SECONDS), now.plusSeconds(OUTSIDE_CLOCK_SKEW_SECONDS));
        saveAuthorization(token, SCOPES, false, true);
        assertInvalidToken(token);
    }

    @Test
    void rejectsTokenSignedByDifferentKeyWithSameKeyId() throws Exception {
        RSAKey otherKey = new RSAKeyGenerator(RSA_BITS).keyID(signingKey.getKeyID()).generate();
        String token = signToken(ACCESS_TOKEN_TYPE, otherKey, now, now.plusSeconds(TOKEN_LIFETIME_SECONDS), null);
        saveAuthorization(token, SCOPES, false, true);
        assertInvalidToken(token);
    }

    @Test
    void rejectsRevokedAccessToken() throws Exception {
        String token = validToken(ACCESS_TOKEN_TYPE);
        saveAuthorization(token, SCOPES, true, true);
        assertInvalidToken(token);
    }

    @Test
    void rejectsSignedTokenMissingFromAuthorizationStore() throws Exception {
        assertInvalidToken(validToken(ACCESS_TOKEN_TYPE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"JWT", "id+jwt"})
    void rejectsIdTokenUsedAsBearerToken(String idTokenType) throws Exception {
        String accessToken = validToken(ACCESS_TOKEN_TYPE);
        String idToken = validToken(idTokenType);
        OAuth2Authorization authorization = saveAuthorization(accessToken, SCOPES, false, false);
        authorizations.save(OAuth2Authorization.from(authorization)
                .token(new OidcIdToken(idToken, now, now.plusSeconds(TOKEN_LIFETIME_SECONDS), Map.of("sub", SUBJECT)))
                .build());
        assertInvalidToken(idToken);
    }

    @Test
    void rejectsAccessTokenWithoutOpenidScope() throws Exception {
        String token = validToken(ACCESS_TOKEN_TYPE);
        saveAuthorization(token, Set.of(OidcScopes.PROFILE), false, true);
        userInfo(fixedDecoder, token)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("insufficient_scope"));
    }

    @Test
    void rejectsAuthorizationWithoutIdToken() throws Exception {
        String token = validToken(ACCESS_TOKEN_TYPE);
        saveAuthorization(token, SCOPES, false, false);
        assertInvalidToken(token);
    }

    @Test
    void returnsOnlyClaimsAllowedByGrantedScopes() throws Exception {
        String token = validToken(ACCESS_TOKEN_TYPE);
        saveAuthorization(token, Set.of(OidcScopes.OPENID), false, true);
        userInfo(fixedDecoder, token).andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value(SUBJECT))
                .andExpect(jsonPath("$.name").doesNotExist())
                .andExpect(jsonPath("$.email").doesNotExist());
    }

    @Test
    void rejectsMissingBearerToken() throws Exception {
        mvc(fixedDecoder).perform(get(USERINFO_ENDPOINT)).andExpect(status().isUnauthorized());
    }

    private void assertInvalidToken(String token) throws Exception {
        userInfo(fixedDecoder, token).andExpect(status().isUnauthorized())
                .andExpect(result -> assertTrue((result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE)
                        + result.getResponse().getContentAsString()).contains("invalid_token")));
    }

    private ResultActions userInfo(JwtDecoder decoder, String token) throws Exception {
        return mvc(decoder).perform(get(USERINFO_ENDPOINT).header(HttpHeaders.AUTHORIZATION, "Bearer " + token));
    }

    private MockMvc mvc(JwtDecoder decoder) {
        BearerTokenAuthenticationFilter bearerFilter = new BearerTokenAuthenticationFilter(
                new ProviderManager(new JwtAuthenticationProvider(decoder)));
        OidcUserInfoEndpointFilter userInfoFilter = new OidcUserInfoEndpointFilter(
                new ProviderManager(new OidcUserInfoAuthenticationProvider(authorizations)), USERINFO_ENDPOINT);
        return MockMvcBuilders.standaloneSetup().addFilters(
                new SecurityContextHolderFilter(new RequestAttributeSecurityContextRepository()),
                bearerFilter, new AnonymousAuthenticationFilter("userinfo-test"), userInfoFilter).build();
    }

    private OAuth2Authorization saveAuthorization(String token, Set<String> scopes, boolean revoked,
                                                  boolean includeIdToken) throws Exception {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token,
                now.minusSeconds(1), now.plusSeconds(TOKEN_LIFETIME_SECONDS), scopes);
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client)
                .id(UUID.randomUUID().toString())
                .principalName(SUBJECT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizedScopes(scopes)
                .token(accessToken, metadata -> metadata.put(
                        OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, revoked));
        if (includeIdToken) {
            builder.token(new OidcIdToken(validToken(ID_TOKEN_TYPE), now, now.plusSeconds(TOKEN_LIFETIME_SECONDS),
                    Map.of("sub", SUBJECT, "name", "UserInfo Test User", "email", "userinfo@example.com")));
        }
        OAuth2Authorization authorization = builder.build();
        authorizations.save(authorization);
        return authorization;
    }

    private String validToken(String type) throws Exception {
        return signToken(type, signingKey, now, now.plusSeconds(TOKEN_LIFETIME_SECONDS), null);
    }

    private String signToken(String type, RSAKey key, Instant issuedAt, Instant expiresAt, Instant notBefore)
            throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID());
        if (type != null) {
            header.type(new JOSEObjectType(type));
        }
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .subject(SUBJECT).issuer("https://auth.example/sdp").audience(client.getClientId())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(issuedAt)).expirationTime(Date.from(expiresAt));
        if (notBefore != null) {
            claims.notBeforeTime(Date.from(notBefore));
        }
        SignedJWT jwt = new SignedJWT(header.build(), claims.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }
}
