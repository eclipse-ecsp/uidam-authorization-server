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

package org.eclipse.ecsp.oauth2.server.core.utils;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants;
import org.eclipse.ecsp.oauth2.server.core.entities.Authorization;
import org.eclipse.ecsp.oauth2.server.core.exception.CustomOauth2AuthorizationException;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.REVOKE_TOKEN_SCOPE;

/**
 * JwtTokenValidator is a utility class for handling JWT tokens.
 * It provides methods to retrieve public keys from JWKSource,
 * parse JWT tokens, and validate them. This implementation supports both
 * KeyStore-based and JWKS-based deployments.
 */
@Component
public class JwtTokenValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenValidator.class);
    private static final String INVALIDATED_KEY = "invalidated";

    private final JWKSource<SecurityContext> jwkSource;
    private final AuthorizationRepository authorizationRepository;
    
    @Value("${authorization.token.hash.algorithm:SHA-256}")
    private String tokenHashAlgorithm;
    
    @Value("${uidam.oauth2.token.hash.salt:}")
    private String tokenHashSalt;

    /**
     * Constructor for JwtTokenValidator.
     * Initializes the validator with JWKSource for dynamic public key resolution
     * and AuthorizationRepository for database-backed token introspection.
     *
     * @param jwkSource the JWK source to retrieve tenant-specific public keys
     * @param authorizationRepository the repository to validate tokens against the database
     */
    public JwtTokenValidator(JWKSource<SecurityContext> jwkSource,
                            AuthorizationRepository authorizationRepository) {
        this.jwkSource = jwkSource;
        this.authorizationRepository = authorizationRepository;
        LOGGER.debug("JwtTokenValidator initialized with JWKSource and AuthorizationRepository");
    }

    /**
     * Gets the public key for the current tenant from the JWKSource.
     * This method supports both KeyStore-based and JWKS-based deployments.
     *
     * @return the RSA public key for JWT verification
     * @throws Exception if an error occurs while loading the public key
     */
    private RSAPublicKey getCurrentTenantPublicKey() throws Exception {
        LOGGER.debug("## getCurrentTenantPublicKey - START");
        try {
            // Create a JWK selector to match RSA keys
            // Note: Not filtering by keyUse since keys may not have the 'use' field set
            JWKMatcher matcher = new JWKMatcher.Builder()
                    .keyType(KeyType.RSA)
                    .build();
            JWKSelector selector = new JWKSelector(matcher);

            // Get matching JWKs from the JWK source
            List<JWK> jwks = jwkSource.get(selector, null);

            if (jwks == null || jwks.isEmpty()) {
                LOGGER.error("No RSA keys found for current tenant");
                throw new IllegalStateException("No RSA keys found for current tenant");
            }

            // Use the first matching RSA key
            JWK jwk = jwks.get(0);
            if (!(jwk instanceof RSAKey)) {
                LOGGER.error("JWK is not an RSA key: {}", jwk.getKeyType());
                throw new IllegalStateException("Expected RSA key but found: " + jwk.getKeyType());
            }

            RSAKey rsaKey = (RSAKey) jwk;
            RSAPublicKey publicKey = rsaKey.toRSAPublicKey();

            LOGGER.debug("Successfully retrieved RSA public key from JWKSource");
            LOGGER.debug("## getCurrentTenantPublicKey - END");
            return publicKey;

        } catch (Exception e) {
            LOGGER.error("Error retrieving public key from JWKSource", e);
            throw e;
        }
    }

    /**
     * Parses the JWT token and retrieves the claims.
     * This method uses the public key from JWKSource to verify the token signature,
     * ensuring compatibility with both KeyStore-based and JWKS-based deployments.
     *
     * @param token the JWT token to parse
     * @return the claims contained in the token
     * @throws CustomOauth2AuthorizationException if the token is invalid or cannot be parsed
     */
    public Claims getClaimsFromToken(String token) {
        LOGGER.debug("## getClaimsFromToken - START");
        try {
            // Get the public key from JWKSource
            RSAPublicKey publicKey = getCurrentTenantPublicKey();

            // Parse and verify the token using the public key
            Claims claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            LOGGER.debug("Successfully parsed and verified JWT token");
            LOGGER.debug("## getClaimsFromToken - END");
            return claims;

        } catch (SecurityException | MalformedJwtException | ExpiredJwtException | UnsupportedJwtException
                 | IllegalArgumentException ex) {
            LOGGER.error("JWT Parser error.", ex);
            throw new CustomOauth2AuthorizationException(CustomOauth2TokenGenErrorCodes.INVALID_TOKEN);
        } catch (Exception ex) {
            LOGGER.error("Unable to parse the Token with JWTParser.", ex);
            throw new CustomOauth2AuthorizationException(CustomOauth2TokenGenErrorCodes.INVALID_TOKEN);
        }
    }

    /**
     * Validates the JWT token by checking its claims and scopes.
     *
     * @param token the JWT token to validate
     * @return true if the token is valid and contains the required scope, false otherwise
     */
    public boolean validateToken(String token) {
        return validateToken(token, REVOKE_TOKEN_SCOPE);
    }

    /**
     * Validates the JWT token by checking its claims and the required scope.
     * This method uses JWKSource to retrieve the correct public key
     * for signature verification, ensuring compatibility with both KeyStore-based
     * and JWKS-based deployments.
     *
     * @param token the JWT token to validate
     * @param requiredScope the scope that must be present in the token
     * @return true if the token is valid and contains the required scope, false otherwise
     */
    public boolean validateToken(String token, String requiredScope) {
        try {
            LOGGER.debug("## validateToken - START");
            Claims claims = getClaimsFromToken(token);
            String scopes = claims.get(AuthorizationServerConstants.SCOPE, String.class);
            List<String> scopeList = scopes != null && !scopes.isEmpty()
                    ? Arrays.asList(scopes.split(" ")) : Collections.emptyList();
            LOGGER.debug("Token scopes: {}", scopeList);
            LOGGER.debug("## validateToken - END");
            return scopeList.contains(requiredScope);

        } catch (Exception e) {
            LOGGER.error("## validateToken - ERROR: Error encountered while validating token.", e);
            return false;
        }
    }
    
    /**
     * Introspects the JWT token by validating against the database (similar to OAuth2 introspect).
     * This method checks:
     * 1. Token signature and claims validity
     * 2. Token exists in the authorization table
     * 3. Token has not been revoked/invalidated
     * 4. Token has not expired
     * 5. Token contains the required scope
     *
     * @param token the JWT token to introspect
     * @param requiredScope the scope that must be present in the token
     * @return true if the token is active and valid, false otherwise
     */
    public boolean introspectToken(String token, String requiredScope) {
        try {
            LOGGER.debug("## introspectToken - START");
            
            // Step 1: Validate JWT signature and extract claims
            Claims claims = getClaimsFromToken(token);
            
            // Step 2: Check scope
            String scopes = claims.get(AuthorizationServerConstants.SCOPE, String.class);
            List<String> scopeList = scopes != null && !scopes.isEmpty()
                    ? Arrays.asList(scopes.split(" ")) : Collections.emptyList();
            
            if (!scopeList.contains(requiredScope)) {
                LOGGER.warn("Token does not contain required scope: {}", requiredScope);
                return false;
            }
            
            // Step 3: Check token in database (introspection)
            boolean isActive = isTokenActiveInDatabase(token);
            
            LOGGER.debug("## introspectToken - END: isActive={}", isActive);
            return isActive;
            
        } catch (Exception e) {
            LOGGER.error("## introspectToken - ERROR: Error encountered while introspecting token.", e);
            return false;
        }
    }
    
    /**
     * Checks if the token is active in the database.
     * This performs database-backed token validation similar to OAuth2 token introspection.
     *
     * @param token the JWT token to check
     * @return true if the token is active in the database, false otherwise
     */
    private boolean isTokenActiveInDatabase(String token) {
        try {
            // Hash the token to match database storage
            String hashedToken = hashToken(token);
            
            // Query the authorization table
            Optional<Authorization> authOptional = authorizationRepository.findByAccessTokenValue(hashedToken);
            
            if (authOptional.isEmpty()) {
                LOGGER.warn("Token not found in database");
                return false;
            }
            
            Authorization authorization = authOptional.get();
            
            // Check if token has been invalidated
            if (isTokenInvalidated(authorization)) {
                LOGGER.warn("Token has been invalidated/revoked");
                return false;
            }
            
            // Check if token has expired
            Instant expiresAt = authorization.getAccessTokenExpiresAt();
            if (expiresAt != null && expiresAt.isBefore(Instant.now())) {
                LOGGER.warn("Token has expired at: {}", expiresAt);
                return false;
            }
            
            LOGGER.debug("Token is active in database");
            return true;
            
        } catch (Exception e) {
            LOGGER.error("Error checking token in database", e);
            return false;
        }
    }
    
    /**
     * Checks if the authorization has been invalidated.
     * The invalidation status is stored in the access_token_metadata field,
     * not in the attributes field.
     *
     * @param authorization the authorization entity
     * @return true if invalidated, false otherwise
     */
    private boolean isTokenInvalidated(Authorization authorization) {
        try {
            String accessTokenMetadata = authorization.getAccessTokenMetadata();
            if (accessTokenMetadata == null || accessTokenMetadata.isEmpty()) {
                return false;
            }
            
            // Parse access_token_metadata JSON and check for invalidated flag
            // Sample metadata contains: "invalidated":true or "metadata.token.invalidated":false
            // We check for "invalidated":true which indicates the token has been revoked
            return accessTokenMetadata.contains("\"" + INVALIDATED_KEY + "\":true");
                    
        } catch (Exception e) {
            LOGGER.error("Error parsing authorization access token metadata", e);
            return false;
        }
    }
    
    /**
     * Hashes the token using the configured algorithm and salt.
     * This matches the hashing logic used by AuthorizationService.
     *
     * @param token the token to hash
     * @return the hashed token in format "algorithm:base64hash"
     */
    private String hashToken(String token) {
        return TokenHashingUtil.hashToken(token, tokenHashAlgorithm, tokenHashSalt);
    }
}