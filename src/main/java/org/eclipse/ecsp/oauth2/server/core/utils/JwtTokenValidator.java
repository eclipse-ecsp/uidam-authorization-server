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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.CustomOauth2AuthorizationException;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_JWT_PUBLIC_KEY_PEM_PATH;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.REVOKE_TOKEN_SCOPE;

/**
 * JwtTokenValidator is a utility class for handling JWT tokens.
 * It provides methods to load a public key, parse JWT tokens, and validate them.
 */
@Component
public class JwtTokenValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenValidator.class);

    private final TenantConfigurationService tenantConfigurationService;
    private static final String LOCAL_FILE_PATH_IDENTIFIER = "/";

    /**
     * Constructor for JwtTokenValidator.
     * Initializes the provider with the TenantConfigurationService for dynamic tenant property resolution.
     *
     * @param tenantConfigurationService the service to retrieve tenant properties
     */
    public JwtTokenValidator(TenantConfigurationService tenantConfigurationService) {
        this.tenantConfigurationService = tenantConfigurationService;
        LOGGER.debug("JwtTokenValidator initialized with TenantConfigurationService");
    }

    /**
     * Gets the public key for the current tenant.
     *
     * @return the public key for JWT verification
     * @throws Exception if an error occurs while loading the public key
     */
    private PublicKey getCurrentTenantPublicKey() throws Exception {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        if (tenantProperties == null) {
            throw new IllegalStateException("No tenant properties found for current tenant");
        }

        LOGGER.debug("## getCurrentTenantPublicKey - START");
        String publicKeyPath = tenantProperties.getKeyStore().get(TENANT_JWT_PUBLIC_KEY_PEM_PATH);
        LOGGER.debug("Loading public key from path: {}", publicKeyPath);

        try {
            InputStream inputStream = null;
            if (publicKeyPath.contains(LOCAL_FILE_PATH_IDENTIFIER)) {
                inputStream = new FileInputStream(new File(publicKeyPath));
            } else {
                inputStream = getClass().getClassLoader().getResourceAsStream(publicKeyPath);
            }
            if (inputStream == null) {
                LOGGER.error("Public key file not found: {}", publicKeyPath);
                throw new FileNotFoundException("Public key file not found: " + publicKeyPath);
            }
            PublicKey publicKey = PublicKeyLoader.loadPublicKey(inputStream);
            LOGGER.debug("Public key successfully loaded from path: {}", publicKeyPath);
            LOGGER.debug("## getCurrentTenantPublicKey - END");
            return publicKey;
        } catch (Exception e) {
            LOGGER.error("Error loading public key from path: {}", publicKeyPath, e);
            throw e;
        }
    }

    /**
     * Parses the JWT token and retrieves the claims.
     *
     * @param token the JWT token to parse
     * @return the claims contained in the token
     * @throws CustomOauth2AuthorizationException if the token is invalid or cannot be parsed
     */
    private Claims getClaimsFromToken(String token) {
        LOGGER.debug("## getClaimsFromToken - START");
        try {
            PublicKey publicKey = getCurrentTenantPublicKey();
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

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
        try {
            LOGGER.debug("## validateToken - START");
            Claims claims = getClaimsFromToken(token);
            String scopes = claims.get(AuthorizationServerConstants.SCOPE, String.class);
            List<String> scopeList = scopes != null && !scopes.isEmpty()
                    ? Arrays.asList(scopes.split(" ")) : Collections.emptyList();
            LOGGER.debug("Token scopes: {}", scopeList);
            LOGGER.debug("## validateToken - END");
            return scopeList.contains(REVOKE_TOKEN_SCOPE);

        } catch (Exception e) {
            LOGGER.error("## validateToken - ERROR: Error encountered while validating token.", e);
            return false;
        }
    }
}