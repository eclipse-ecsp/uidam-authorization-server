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

package org.eclipse.ecsp.oauth2.server.core.authentication.customizer;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * The FederatedIdentityIdTokenCustomizer class implements the OAuth2TokenCustomizer interface with JwtEncodingContext
 * as its type. This class is used to map a user’s claims from an authentication provider to the id_token produced by
 * Spring Authorization Server. It contains a set of standard id_token claims that are used in the customization of the
 * token.
 */
public final class FederatedIdentityIdTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    // A set of standard id_token claims
    private static final Set<String> ID_TOKEN_CLAIMS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            IdTokenClaimNames.ISS,
            IdTokenClaimNames.SUB,
            IdTokenClaimNames.AUD,
            IdTokenClaimNames.EXP,
            IdTokenClaimNames.IAT,
            IdTokenClaimNames.AUTH_TIME,
            IdTokenClaimNames.NONCE,
            IdTokenClaimNames.ACR,
            IdTokenClaimNames.AMR,
            IdTokenClaimNames.AZP,
            IdTokenClaimNames.AT_HASH,
            IdTokenClaimNames.C_HASH
    )));

    /**
     * This method customizes the token claims based on the token type and the principal's claims.
     * It removes any conflicting claims and standard id_token claims that could cause problems with clients.
     * Then it adds all other claims directly to id_token.
     *
     * @param context the JwtEncodingContext to be customized.
     */
    @Override
    public void customize(JwtEncodingContext context) {
        if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            mergeFederatedClaims(context.getClaims(), context.getPrincipal());
        }
    }

    /**
     * Merges the federated (third-party IdP, e.g. Cognito/Google/Azure) user claims onto the
     * id_token claims currently being built. This is a no-op when the principal is not a
     * federated {@link OAuth2AuthenticationToken} (e.g. internal username/password logins),
     * so it is safe to call unconditionally from any id_token claim-building code path.
     *
     * <p>Conflicting claims already set by this authorization server, as well as the standard
     * id_token claims that could cause problems with clients (iss, sub, aud, exp, iat, etc.),
     * are stripped from the third-party claims before merging so they never override the
     * authorization server's own values.
     *
     * @param claimsBuilder the JwtClaimsSet.Builder for the id_token currently being built.
     * @param principal the Authentication object for the current token request.
     */
    public static void mergeFederatedClaims(JwtClaimsSet.Builder claimsBuilder, Authentication principal) {
        if (!(principal instanceof OAuth2AuthenticationToken)) {
            return;
        }
        Map<String, Object> thirdPartyClaims = extractClaims(principal);
        claimsBuilder.claims(existingClaims -> {
            // Remove conflicting claims set by this authorization server
            existingClaims.keySet().forEach(thirdPartyClaims::remove);

            // Remove standard id_token claims that could cause problems with clients
            ID_TOKEN_CLAIMS.forEach(thirdPartyClaims::remove);

            // Add all other claims directly to id_token
            existingClaims.putAll(thirdPartyClaims);
        });
    }

    /**
     * This method extracts the claims from the principal.
     *
     * <p>Returns a new, mutable copy: {@link OAuth2User#getAttributes()} returns an unmodifiable
     * map, and {@link #mergeFederatedClaims(JwtClaimsSet.Builder, Authentication)} needs to remove
     * entries from the result before merging it into the id_token claims.
     *
     * @param principal the Authentication object from which to extract claims.
     * @return a mutable map of the extracted claims.
     */
    private static Map<String, Object> extractClaims(Authentication principal) {
        OAuth2AuthenticationToken oauth2AuthenticationToken = (OAuth2AuthenticationToken) principal;
        OAuth2User oauth2User = oauth2AuthenticationToken.getPrincipal();
        return new LinkedHashMap<>(oauth2User.getAttributes());
    }

}