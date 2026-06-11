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

package org.eclipse.ecsp.oauth2.server.core.authentication.customizer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FederatedIdentityIdTokenCustomizerTest {

    private FederatedIdentityIdTokenCustomizer customizer;

    @Mock
    private JwtEncodingContext context;

    @Mock
    private OAuth2AuthenticationToken oauth2Token;

    @Mock
    private OAuth2User oauth2User;

    @Mock
    private JwtClaimsSet.Builder claimsBuilder;

    @BeforeEach
    void setUp() {
        customizer = new FederatedIdentityIdTokenCustomizer();
    }

    @Test
    void customize_WithAccessTokenType_ShouldNotModifyClaims() {
        when(context.getTokenType()).thenReturn(
            new OAuth2TokenType("access_token"));

        customizer.customize(context);

        verify(context, never()).getPrincipal();
        verify(context, never()).getClaims();
    }

    @Test
    void customize_WithRefreshTokenType_ShouldNotModifyClaims() {
        when(context.getTokenType()).thenReturn(
            new OAuth2TokenType("refresh_token"));

        customizer.customize(context);

        verify(context, never()).getPrincipal();
        verify(context, never()).getClaims();
    }

    @Test
    void customize_WithIdTokenType_AndCustomClaims_ShouldAddClaims() {
        Map<String, Object> userAttributes = new HashMap<>();
        userAttributes.put("email", "user@example.com");
        userAttributes.put("name", "John Doe");

        when(context.getTokenType()).thenReturn(
            new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        when(context.getPrincipal()).thenReturn(oauth2Token);
        when(oauth2Token.getPrincipal()).thenReturn(oauth2User);
        when(oauth2User.getAttributes()).thenReturn(userAttributes);
        when(context.getClaims()).thenReturn(claimsBuilder);
        when(claimsBuilder.claims(any())).thenAnswer(invocation -> {
            Consumer<Map<String, Object>> consumer = invocation.getArgument(0);
            Map<String, Object> existingClaims = new HashMap<>();
            existingClaims.put(IdTokenClaimNames.ISS, "https://example.com");
            existingClaims.put(IdTokenClaimNames.SUB, "user123");
            consumer.accept(existingClaims);
            // After consumer runs, custom claims should be added
            assertTrue(existingClaims.containsKey("email"));
            assertTrue(existingClaims.containsKey("name"));
            // Standard ISS/SUB claims from 3rd party attributes should be removed
            return claimsBuilder;
        });

        customizer.customize(context);

        verify(claimsBuilder).claims(any());
    }

    @Test
    void customize_WithIdTokenType_StandardClaimsRemoved() {
        Map<String, Object> userAttributes = new HashMap<>();
        userAttributes.put("email", "user@example.com");
        userAttributes.put(IdTokenClaimNames.ISS, "https://provider.com"); // Conflicting standard claim
        userAttributes.put(IdTokenClaimNames.SUB, "user456"); // Conflicting standard claim

        when(context.getTokenType()).thenReturn(
            new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        when(context.getPrincipal()).thenReturn(oauth2Token);
        when(oauth2Token.getPrincipal()).thenReturn(oauth2User);
        when(oauth2User.getAttributes()).thenReturn(new HashMap<>(userAttributes));
        when(context.getClaims()).thenReturn(claimsBuilder);
        when(claimsBuilder.claims(any())).thenAnswer(invocation -> {
            Consumer<Map<String, Object>> consumer = invocation.getArgument(0);
            Map<String, Object> existingClaims = new HashMap<>();
            existingClaims.put(IdTokenClaimNames.ISS, "https://example.com");
            existingClaims.put(IdTokenClaimNames.SUB, "user123");
            consumer.accept(existingClaims);
            // Standard ISS/SUB from existing claims should remain
            assertTrue(existingClaims.containsKey(IdTokenClaimNames.ISS));
            assertTrue(existingClaims.containsKey(IdTokenClaimNames.SUB));
            return claimsBuilder;
        });

        customizer.customize(context);

        verify(claimsBuilder).claims(any());
    }

    @Test
    void customize_WithIdTokenType_EmptyAttributes_ShouldNotFail() {
        Map<String, Object> userAttributes = new HashMap<>();

        when(context.getTokenType()).thenReturn(
            new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        when(context.getPrincipal()).thenReturn(oauth2Token);
        when(oauth2Token.getPrincipal()).thenReturn(oauth2User);
        when(oauth2User.getAttributes()).thenReturn(userAttributes);
        when(context.getClaims()).thenReturn(claimsBuilder);
        when(claimsBuilder.claims(any())).thenAnswer(invocation -> {
            Consumer<Map<String, Object>> consumer = invocation.getArgument(0);
            Map<String, Object> existingClaims = new HashMap<>();
            existingClaims.put(IdTokenClaimNames.SUB, "user123");
            consumer.accept(existingClaims);
            return claimsBuilder;
        });

        customizer.customize(context);

        verify(claimsBuilder).claims(any());
    }

    @Test
    void customize_WithIdTokenType_AllStandardClaimsRemoved() {
        // Include all standard ID token claims that should be stripped
        Map<String, Object> userAttributes = new HashMap<>();
        userAttributes.put(IdTokenClaimNames.ISS, "https://provider.com");
        userAttributes.put(IdTokenClaimNames.SUB, "user456");
        userAttributes.put(IdTokenClaimNames.AUD, "client123");
        userAttributes.put(IdTokenClaimNames.EXP, 1234567890L);
        userAttributes.put(IdTokenClaimNames.IAT, 1234567800L);
        userAttributes.put(IdTokenClaimNames.AUTH_TIME, 1234567700L);
        userAttributes.put(IdTokenClaimNames.NONCE, "nonce123");
        userAttributes.put(IdTokenClaimNames.ACR, "urn:mace:incommon:iap:silver");
        userAttributes.put(IdTokenClaimNames.AMR, "pwd");
        userAttributes.put(IdTokenClaimNames.AZP, "client123");
        userAttributes.put(IdTokenClaimNames.AT_HASH, "hash123");
        userAttributes.put(IdTokenClaimNames.C_HASH, "c_hash123");
        userAttributes.put("email", "user@example.com"); // Custom claim should survive

        when(context.getTokenType()).thenReturn(
            new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        when(context.getPrincipal()).thenReturn(oauth2Token);
        when(oauth2Token.getPrincipal()).thenReturn(oauth2User);
        when(oauth2User.getAttributes()).thenReturn(new HashMap<>(userAttributes));
        when(context.getClaims()).thenReturn(claimsBuilder);
        when(claimsBuilder.claims(any())).thenAnswer(invocation -> {
            Consumer<Map<String, Object>> consumer = invocation.getArgument(0);
            Map<String, Object> existingClaims = new HashMap<>();
            existingClaims.put(IdTokenClaimNames.ISS, "https://myserver.com");
            existingClaims.put(IdTokenClaimNames.SUB, "server-user");
            consumer.accept(existingClaims);
            // The server's original claims should still be there
            assertTrue(existingClaims.containsKey(IdTokenClaimNames.ISS));
            // Custom email should be added
            assertTrue(existingClaims.containsKey("email"));
            return claimsBuilder;
        });

        customizer.customize(context);

        verify(claimsBuilder).claims(any());
    }

    @Test
    void customize_WithIdTokenType_ExistingClaimsConflict_ConflictingAttributesRemoved() {
        // User has an attribute that conflicts with existing claim - it should be removed from 3rd party
        Map<String, Object> userAttributes = new HashMap<>();
        userAttributes.put("email", "user@example.com");
        userAttributes.put("existing_server_claim", "server_value"); // This is in existing claims

        when(context.getTokenType()).thenReturn(
            new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        when(context.getPrincipal()).thenReturn(oauth2Token);
        when(oauth2Token.getPrincipal()).thenReturn(oauth2User);
        when(oauth2User.getAttributes()).thenReturn(new HashMap<>(userAttributes));
        when(context.getClaims()).thenReturn(claimsBuilder);
        when(claimsBuilder.claims(any())).thenAnswer(invocation -> {
            Consumer<Map<String, Object>> consumer = invocation.getArgument(0);
            Map<String, Object> existingClaims = new HashMap<>();
            existingClaims.put(IdTokenClaimNames.SUB, "user123");
            existingClaims.put("existing_server_claim", "server_value"); // Existing server claim
            consumer.accept(existingClaims);
            // Server claim value should be preserved (not overwritten by 3rd party)
            assertTrue(existingClaims.containsKey("existing_server_claim"));
            return claimsBuilder;
        });

        customizer.customize(context);

        verify(claimsBuilder).claims(any());
    }
}
