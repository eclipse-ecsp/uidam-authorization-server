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
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.REVOKE_TOKEN_SCOPE;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtTokenValidatorTest {

    public static final int EXPIRATION_MILLIS = 60000;

    @Mock
    private JWKSource<SecurityContext> jwkSource;
    
    @Mock
    private AuthorizationRepository authorizationRepository;

    private JwtTokenValidator jwtTokenValidator;
    
    private PublicKey publicKey;

    @BeforeEach
    void setUp() throws Exception {
        this.publicKey = PublicKeyLoader.loadPublicKey(getClass().getClassLoader()
                .getResourceAsStream("uidampubkey.pem"));

        MockitoAnnotations.openMocks(this);
        
        // Mock JWKSource to return RSA key with the public key
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) this.publicKey).build();
        when(jwkSource.get(any(JWKSelector.class), any()))
                .thenReturn(Collections.singletonList((JWK) rsaKey));
        
        // Initialize JwtTokenValidator with JWKSource and AuthorizationRepository
        jwtTokenValidator = new JwtTokenValidator(jwkSource, authorizationRepository);
    }

    @Test
    void testValidateTokenWithExpiredToken() {
        // Create a test token
        String token = "eyJ4NXQjUzI1NiI6Ikd2ME40UnRZczh5NzlJSzVPVkU3Vk9pRFNlQjNvNHVNNTg2dGRn"
                + "NEtQenciLCJraWQiOiI5ZGEzMzQ2MC00NGIwLTQzMmUtOTFiYy05YjczZjIzZjQ4ZDYiLCJ0eXA"
                + "iOiJhdCtqd3QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImFjY291bnROYW1lIjoiaW"
                + "duaXRlIiwiYWNjb3VudFR5cGUiOiJSb290IiwiaXNzIjoiaHR0cHM6Ly91aWRhbS1hdXRob3Jpem"
                + "F0aW9uLXNlcnZlci5la3MtaWduaXRlLWRldi5pYy5hd3MuaGFybWFuZGV2LmNvbSIsImF1ZCI6In"
                + "Rlc3QtcG9ydGFsIiwiYWNjb3VudElkIjoiNmY0NTI2MjQtYzRlMy00MGZmLWJhMjktZmU5MDgyNz"
                + "A1ZjUwIiwibmJmIjoxNzI0ODQwNDA4LCJ1c2VyX2lkIjoiMTUwOTUzNjYzNDgyMjQxNTk5NDE5Mz"
                + "U5MDI2MTQyNDI0Iiwic2NvcGUiOiJNYW5hZ2VVc2VycyIsInRlbmFudElkIjoiSWduaXRlMDEiLC"
                + "JzY29wZXMiOlsiTWFuYWdlVXNlcnMiXSwiZXhwIjoxNzI0ODQ0MDA4LCJsYXN0X2xvZ29uIjoiMj"
                + "AyNC0wOC0yOFQxMDoxOTo1MS41OTAyMDVaIiwiaWF0IjoxNzI0ODQwNDA4LCJqdGkiOiJjYTk2ZT"
                + "QxMC1hODU5LTQwYzktODFjZi1iYWNmOGQ1ZjJjMWQiLCJ1c2VybmFtZSI6ImFkbWluIn0.MU5dkF"
                + "7l8yzgH1OXU_A8sw9ALiLHnodyLCToIx9WzdZdcaO6VNOdkyZcWyxIKie5ayCh0t66BppW05E7q-9U"
                + "gl_CiTsogJoH0igN1hTeXuGi23QW8bZy9O8IHIiuhVXX3hOyOuVvYhlanBrJnKyXNq8CYFA_hu9BHi"
                + "k_DHSxhfR4N90f6WNQMi8hE7sRaq-exmYnUYy9gpOyJz8X2N5dA61Hw9fGGNUBYWvTx491t63V0CaU"
                + "hwAI5GsAfYTfQkKeUBdIlFVsUGCZojGheQaTGap0GB5hIwCsqlPYlmOPBigTyeYYmDjGZik8SNlBtmJ"
                + "4buDkjvlouXhIhfwK4nqeHg";

        // Test validateToken
        assertFalse(jwtTokenValidator.validateToken(token));
    }

    @Test
    void testValidateTokenWithValidToken() throws Exception {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", REVOKE_TOKEN_SCOPE);
        PrivateKey privateKey = KeyStoreLoader.loadPrivateKey("uidamauthserver.jks",
                "uidam-dev", "uidam-test-pwd", "uidam-test-pwd");
        // Create a test token
        String token = createValidToken(claims, EXPIRATION_MILLIS, privateKey);
        // Test validateToken
        boolean validateToken = jwtTokenValidator.validateToken(token);
        assertTrue(validateToken);
    }

    @Test
    void testValidateToken_InvalidToken() {
        // Create an invalid token
        String invalidToken = "invalid.token";
        // Test validateToken with invalid token
        assertFalse(jwtTokenValidator.validateToken(invalidToken));
    }
    
    @Test
    void testIntrospectToken_RevokedTokenWithRealMetadata() throws Exception {
        // Arrange - create valid JWT
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "SelfManage");
        PrivateKey privateKey = KeyStoreLoader.loadPrivateKey("uidamauthserver.jks",
                "uidam-dev", "uidam-test-pwd", "uidam-test-pwd");
        final String token = createValidToken(claims, EXPIRATION_MILLIS, privateKey);
        
        // Mock authorization with real-world metadata showing revoked token
        org.eclipse.ecsp.oauth2.server.core.entities.Authorization authorization = 
                new org.eclipse.ecsp.oauth2.server.core.entities.Authorization();
        authorization.setAccessTokenValue("hashed-token");
        final int tokenValiditySeconds = 3600;
        authorization.setAccessTokenExpiresAt(java.time.Instant.now().plusSeconds(tokenValiditySeconds));
        
        // Real metadata format from production with "invalidated":true
        String metadata = "{\"@class\":\"java.util.Collections$UnmodifiableMap\","
                + "\"metadata.token.invalidated\":false,"
                + "\"invalidated\":true,"
                + "\"invalidationReason\":\"User requested logout\"}";
        authorization.setAccessTokenMetadata(metadata);
        
        when(authorizationRepository.findByAccessTokenValue(any()))
                .thenReturn(java.util.Optional.of(authorization));
        
        // Act
        boolean result = jwtTokenValidator.introspectToken(token, "SelfManage");
        
        // Assert
        assertFalse(result, "Token with invalidated:true in metadata should be rejected");
    }
    
    @Test
    void testIntrospectToken_ActiveTokenWithRealMetadata() throws Exception {
        // Arrange - create valid JWT
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "SessionManagement");
        PrivateKey privateKey = KeyStoreLoader.loadPrivateKey("uidamauthserver.jks",
                "uidam-dev", "uidam-test-pwd", "uidam-test-pwd");
        final String token = createValidToken(claims, EXPIRATION_MILLIS, privateKey);
        
        // Mock authorization with metadata showing active token
        org.eclipse.ecsp.oauth2.server.core.entities.Authorization authorization = 
                new org.eclipse.ecsp.oauth2.server.core.entities.Authorization();
        authorization.setAccessTokenValue("hashed-token");
        final int tokenValiditySeconds = 3600;
        authorization.setAccessTokenExpiresAt(java.time.Instant.now().plusSeconds(tokenValiditySeconds));
        
        // Metadata with invalidated:false (active token)
        String metadata = "{\"@class\":\"java.util.Collections$UnmodifiableMap\","
                + "\"metadata.token.invalidated\":false,"
                + "\"invalidated\":false}";
        authorization.setAccessTokenMetadata(metadata);
        
        when(authorizationRepository.findByAccessTokenValue(any()))
                .thenReturn(java.util.Optional.of(authorization));
        
        // Act
        boolean result = jwtTokenValidator.introspectToken(token, "SessionManagement");
        
        // Assert
        assertTrue(result, "Token with invalidated:false in metadata should be accepted");
    }
    
    @Test
    void testIntrospectToken_TokenNotFoundInDatabase() throws Exception {
        // Arrange
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", "SessionManagement");
        PrivateKey privateKey = KeyStoreLoader.loadPrivateKey("uidamauthserver.jks",
                "uidam-dev", "uidam-test-pwd", "uidam-test-pwd");
        final String token = createValidToken(claims, EXPIRATION_MILLIS, privateKey);
        
        // Mock repository to return empty (token not in database)
        when(authorizationRepository.findByAccessTokenValue(any()))
                .thenReturn(java.util.Optional.empty());
        
        // Act
        boolean result = jwtTokenValidator.introspectToken(token, "SessionManagement");
        
        // Assert
        assertFalse(result, "Token not in database should be rejected");
    }

    public static String createValidToken(Map<String, Object> claims, long expirationMillis, PrivateKey privateKey) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expirationMillis))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }
}