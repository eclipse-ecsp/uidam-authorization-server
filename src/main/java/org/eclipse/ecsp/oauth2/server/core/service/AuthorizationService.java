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

package org.eclipse.ecsp.oauth2.server.core.service;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.audit.context.UserActorContext;
import org.eclipse.ecsp.oauth2.server.core.audit.enums.AuditEventType;
import org.eclipse.ecsp.oauth2.server.core.authentication.CustomWebAuthenticationDetails;
import org.eclipse.ecsp.oauth2.server.core.authentication.CustomWebAuthenticationDetailsMixin;
import org.eclipse.ecsp.oauth2.server.core.authentication.CustomWebAuthenticationDetailsSource;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationTokenMixin;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants;
import org.eclipse.ecsp.oauth2.server.core.entities.Authorization;
import org.eclipse.ecsp.oauth2.server.core.exception.CustomOauth2AuthorizationException;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.eclipse.ecsp.oauth2.server.core.request.dto.RevokeTokenRequest;
import org.eclipse.ecsp.oauth2.server.core.utils.JwtTokenValidator;
import org.eclipse.ecsp.oauth2.server.core.utils.TokenHashingUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import static org.eclipse.ecsp.oauth2.server.core.utils.ObjectMapperUtils.parseMap;
import static org.eclipse.ecsp.oauth2.server.core.utils.ObjectMapperUtils.writeMap;

/**
 * This class is a custom implementation of the OAuth2AuthorizationService interface.
 */
@Component
public class AuthorizationService implements OAuth2AuthorizationService {    
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationService.class);
    private static final int BEGIN_INDEX = 7;

    private static final String COMPONENT_NAME = "uidam-authorization-server";
    
    // Browser details constants
    private static final String UNKNOWN = "unknown";
    private static final String USER_AGENT_KEY = "user_agent";
    private static final String IP_ADDRESS_KEY = "ip_address";
    private static final String ACCEPT_LANGUAGE_KEY = "accept_language";
    private static final String REFERER_KEY = "referer";
    private static final String SESSION_ID_KEY = "session_id";
    private static final String CAPTURED_AT_KEY = "captured_at";
    
    private final AuthorizationRepository authorizationRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JwtTokenValidator jwtTokenValidator;
    private final AuditLogger auditLogger;
   
    @Value("${uidam.oauth2.token.hash.algorithm}")
    private String tokenHashAlgorithm;
    
    @Value("${uidam.oauth2.token.hash.salt:}")
    private String tokenHashSalt;

    /**
     * Constructs a new IgniteOauth2AuthorizationService with the given repositories.
     *
     * @param authorizationRepository the repository to use for interacting with Authorization instances in the database
     * @param registeredClientRepository the repository to use for retrieving RegisteredClient instances
     * @param jwtTokenValidator the validator to use for JWT token validation
     * @param auditLogger the audit logger for logging authorization events
     */
    public AuthorizationService(AuthorizationRepository authorizationRepository,
                                RegisteredClientRepository registeredClientRepository,
                                JwtTokenValidator jwtTokenValidator,
                                AuditLogger auditLogger) {
        LOGGER.debug("## IgniteOAuth2AuthorizationService - START");
        Assert.notNull(authorizationRepository, "authorizationRepository cannot be null");
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        Assert.notNull(jwtTokenValidator, "jwtTokenValidator cannot be null");
        Assert.notNull(auditLogger, "auditLogger cannot be null");
        this.authorizationRepository = authorizationRepository;
        this.registeredClientRepository = registeredClientRepository;
        this.jwtTokenValidator = jwtTokenValidator;
        this.auditLogger = auditLogger;

        ClassLoader classLoader = AuthorizationService.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        this.objectMapper.addMixIn(CustomUserPwdAuthenticationToken.class, CustomUserPwdAuthenticationTokenMixin.class);
        this.objectMapper.addMixIn(CustomWebAuthenticationDetails.class, CustomWebAuthenticationDetailsMixin.class);
        LOGGER.debug("## IgniteOAuth2AuthorizationService - END");
    }

    /**
     * Saves the given OAuth2Authorization instance to the database.
     *
     * @param authorization the OAuth2Authorization instance to save
     */
    @Override
    public void save(OAuth2Authorization authorization) {
        LOGGER.debug("## save - START");
        Assert.notNull(authorization, "authorization cannot be null");
        
        // Capture browser details from authentication if available
        OAuth2Authorization enrichedAuthorization = enrichAuthorizationWithBrowserDetails(authorization);
        
        Authorization uidamAuthorization = toEntity(enrichedAuthorization);
        
        // Normalize username to lowercase for case-insensitive username handling
        if (StringUtils.hasText(uidamAuthorization.getPrincipalName())) {
            String normalizedPrincipalName = uidamAuthorization.getPrincipalName().toLowerCase();
            uidamAuthorization.setPrincipalName(normalizedPrincipalName);
            LOGGER.debug("## Normalized principalName to lowercase: {}", normalizedPrincipalName);
        }
        
        if (StringUtils.hasText(uidamAuthorization.getAccessTokenValue())) {
            String hashedToken = hashToken(uidamAuthorization.getAccessTokenValue());
            uidamAuthorization.setAccessTokenValue(hashedToken);
        }
        if (StringUtils.hasText(uidamAuthorization.getRefreshTokenValue())) {
            String hashedToken = hashToken(uidamAuthorization.getRefreshTokenValue());
            uidamAuthorization.setRefreshTokenValue(hashedToken);
        }
        
        if (StringUtils.hasText(uidamAuthorization.getOidcIdTokenValue())) {
            String hashedToken = hashToken(uidamAuthorization.getOidcIdTokenValue());
            uidamAuthorization.setOidcIdTokenValue(hashedToken);
        }

        this.authorizationRepository.save(uidamAuthorization);
        LOGGER.debug("## save - END");
    }

    /**
     * Removes the given OAuth2Authorization instance from the database.
     *
     * @param authorization the OAuth2Authorization instance to remove
     */
    @Override
    public void remove(OAuth2Authorization authorization) {
        LOGGER.debug("## remove - START");
        Assert.notNull(authorization, "authorization cannot be null");
        this.authorizationRepository.deleteById(authorization.getId());
        LOGGER.debug("## remove - END");
    }

    /**
     * Finds the OAuth2Authorization instance with the given id.
     *
     * @param id the id of the OAuth2Authorization instance to find
     * @return the found OAuth2Authorization instance, or null if none was found
     */
    @Override
    public OAuth2Authorization findById(String id) {
        LOGGER.debug("## findById - START");
        Assert.hasText(id, "id cannot be empty");
        LOGGER.debug("## findById - END");
        return this.authorizationRepository.findById(id).map(this::toObject).orElse(null);
    }

    /**
     * Finds the OAuth2Authorization instance with the given token and token type.
     *
     * @param token the token of the OAuth2Authorization instance to find
     * @param tokenType the token type of the OAuth2Authorization instance to find
     * @return the found OAuth2Authorization instance, or null if none was found
     */
    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        LOGGER.debug("## findByToken - START");
        Assert.hasText(token, "token cannot be empty");

        Optional<Authorization> result;
        if (tokenType == null) {
            result = this.authorizationRepository
                .findByStateOrAuthCodeOrAccessTokenOrRefreshTokenOrOidcIdTokenOrUserCodeOrDeviceCode(token,
                        hashToken(token));
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByState(token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByAuthorizationCodeValue(token);
        } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByAccessTokenValue(hashToken(token));
        } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByRefreshTokenValue(hashToken(token));
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByOidcIdTokenValue(hashToken(token));
        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByUserCodeValue(token);
        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            result = this.authorizationRepository.findByDeviceCodeValue(token);
        } else {
            result = Optional.empty();
        }
        LOGGER.debug("## findByToken - END");
        if (result.isPresent()) {
            updateTokenWithHashToken(result.get(), token, hashToken(token));
        }
        
        return result.map(this::toObject).orElse(null);
    }

    /**
     * This method is used to revoke the token of a user/client.
     *
     * @param revokeTokenRequest the request to revoke tokens of a user/client
     * @param token the token to check whether it has the correct scope to revoke tokens of a user/client or not
     * @return a response indicating whether the method executed successfully or not
     */
    public String revokeToken(RevokeTokenRequest revokeTokenRequest, String token) {
        LOGGER.debug("revokeToken START");
        if (!isValidToken(token)) {
            LOGGER.error("## Token validation failed!");
            logAuthorizationFailure(AuditEventType.AUTHZ_FAILURE_REVOKED_TOKEN, 
                                   revokeTokenRequest.getUsername(), 
                                   revokeTokenRequest.getClientId());
            throw new CustomOauth2AuthorizationException(CustomOauth2TokenGenErrorCodes.INVALID_TOKEN);
        }
        String principalName;
        if (Optional.ofNullable(revokeTokenRequest.getUsername()).isPresent()) {
            principalName = revokeTokenRequest.getUsername();
        } else {
            principalName = revokeTokenRequest.getClientId();
        }
        if (!Optional.ofNullable(principalName).isPresent()) {
            LOGGER.error("## Principal name is missing in the request body!");
            throw new CustomOauth2AuthorizationException(CustomOauth2TokenGenErrorCodes.MISSING_FIELD_IN_REQUEST_BODY);
        }
        return revokenTokensInDb(principalName);
    }

    /**
     * This method is used to revoke the token in the database for a given principal name.
     * It retrieves the active tokens for the principal name and invalidates them.
     * If no active tokens are found, it returns a message indicating that no active token exists.
     *
     * @param principalName the name of the principal whose token needs to be revoked
     * @return a response indicating whether the token was revoked successfully or not
     */
    public String revokenTokensInDb(String principalName) {
        try {
            // Normalize principal name to lowercase for case-insensitive matching
            String normalizedPrincipalName = principalName != null ? principalName.toLowerCase() : principalName;
            LOGGER.info("Revoking tokens for principal");
            List<Authorization> result = this.authorizationRepository
                .findByPrincipalNameAndAccessTokenExpiresAt(normalizedPrincipalName, Instant.now());
            List<OAuth2Authorization> oauth2Authorizations = result.stream().map(this::toObject).toList();
            List<Authorization> authorizations = oauth2Authorizations.stream().map(
                    authorization -> toEntity(invalidate(authorization, authorization.getAccessToken().getToken())))
                .toList();
            if (authorizations.isEmpty()) {
                LOGGER.info("No active token found for principal");
                return IgniteOauth2CoreConstants.NO_ACTIVE_TOKEN_EXIST;
            }
            this.authorizationRepository.saveAll(authorizations);
            LOGGER.debug("Token revoked successfully");
        } catch (Exception ex) {
            LOGGER.error("## Failed to process revoke token, exception occurs: ", ex);
            throw new CustomOauth2AuthorizationException(CustomOauth2TokenGenErrorCodes.SERVER_ERROR);
        }
        return IgniteOauth2CoreConstants.REVOKE_TOKEN_SUCCESS_RESPONSE;
    }
    
    /**
     * This method is used to revoke the token for a given principal name and client ID. It retrieves the active tokens
     * for the principal name and client ID and invalidates them. This method properly handles both access tokens and
     * refresh tokens by finding authorizations where either token type is still valid and ensuring both are properly
     * revoked. If no active tokens are found, it returns a message indicating that no active token exists.
     *
     * @param principalName the name of the principal whose token needs to be revoked
     * @param clientId the client ID associated with the token
     * @return a response indicating whether the token was revoked successfully or not
     */
    public String revokenTokenByPrincipalAndClientId(String principalName, String clientId) {
        try {
            // Normalize principal name to lowercase for case-insensitive matching
            String normalizedPrincipalName = principalName != null ? principalName.toLowerCase() : principalName;
            LOGGER.info("## revoking token for principalName: {}", normalizedPrincipalName);
            // Use the new repository method that considers both access and refresh token validity
            List<Authorization> result = this.authorizationRepository
                    .findByPrincipalNameClientAndValidTokens(normalizedPrincipalName, clientId, Instant.now());
            List<OAuth2Authorization> oauth2Authorizations = result.stream().map(this::toObject).toList();
            
            // Process each authorization to invalidate all tokens properly
            List<Authorization> authorizations = oauth2Authorizations.stream().map(authorization -> {
                OAuth2Authorization invalidatedAuth;
                
                // Check if refresh token exists and is valid - if so, invalidate via refresh token
                // This ensures both access and refresh tokens are properly invalidated
                OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
                if (refreshToken != null && !refreshToken.isInvalidated()) {
                    LOGGER.debug("## Invalidating via refresh token to ensure complete revocation");
                    invalidatedAuth = invalidate(authorization, refreshToken.getToken());
                } else {
                    // Fall back to access token invalidation
                    LOGGER.debug("## Invalidating via access token");
                    invalidatedAuth = invalidate(authorization, authorization.getAccessToken().getToken());
                }
                
                return toEntity(invalidatedAuth);
            }).toList();
            
            if (authorizations.isEmpty()) {
                LOGGER.info("## no active token for user/client id!");
                return IgniteOauth2CoreConstants.NO_ACTIVE_TOKEN_EXIST;
            }
            this.authorizationRepository.saveAll(authorizations);
            LOGGER.debug("## token revoked successfully - both access and refresh tokens invalidated");
        } catch (Exception ex) {
            LOGGER.error("## Failed to process revoke token, exception occurs: ", ex);
            throw new CustomOauth2AuthorizationException(CustomOauth2TokenGenErrorCodes.SERVER_ERROR);
        }
        return IgniteOauth2CoreConstants.REVOKE_TOKEN_SUCCESS_RESPONSE;
    }

    /**
     * This method is used to validate the provided token.
     * It checks if the token contains the "Bearer" keyword, and if so, it retrieves the OAuth2Authorization instance
     * associated with the token.
     * It then checks if the OAuth2Authorization instance exists, if it has the "revoke_token" scope, if the token is
     * not expired, and if the token is active.
     *
     * @param token the token to validate
     * @return true if the token is valid, false otherwise
     */
    private boolean isValidToken(String token) {
        LOGGER.debug("isValidToken START");
        if (token.contains(IgniteOauth2CoreConstants.BEARER)) {
            return jwtTokenValidator.validateToken(token.substring(BEGIN_INDEX));
        }
        return false;
    }

    /**
     * This method is used to invalidate a given OAuth2Token within an OAuth2Authorization.
     * It creates a new OAuth2Authorization instance with the same attributes as the original, but with the provided
     * token invalidated.
     * The invalidated token is marked by adding a metadata entry with key "invalidated" and value true.
     *
     * @param <T> the type of the OAuth2Token to invalidate
     * @param authorization the original OAuth2Authorization
     * @param token the OAuth2Token to invalidate
     * @return a new OAuth2Authorization instance with the provided token invalidated
     */
    private <T extends OAuth2Token> OAuth2Authorization invalidate(
        OAuth2Authorization authorization, T token) {

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
            .token(token,
                metadata ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

        if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
            authorizationBuilder.token(
                authorization.getAccessToken().getToken(),
                metadata ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

            OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
            if (authorizationCode != null && !authorizationCode.isInvalidated()) {
                authorizationBuilder.token(
                    authorizationCode.getToken(),
                    metadata ->
                        metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
            }
        }

        return authorizationBuilder.build();
    }

    /**
     * This method is used to convert an Authorization entity into an OAuth2Authorization object.
     * It retrieves the RegisteredClient associated with the Authorization entity and checks if it exists.
     * If the RegisteredClient does not exist, it throws a DataRetrievalFailureException.
     * It then builds an OAuth2Authorization object with the attributes from the Authorization entity.
     *
     * @param entity the Authorization entity to convert
     * @return the converted OAuth2Authorization object
     */
    private OAuth2Authorization toObject(Authorization entity) {
        LOGGER.debug("## toObject - START");
        RegisteredClient registeredClient = this.registeredClientRepository.findById(entity.getRegisteredClientId());
        if (registeredClient == null) {
            LOGGER.debug("Registered Client is null");
            throw new DataRetrievalFailureException(
                "The RegisteredClient with id '" + entity.getRegisteredClientId()
                    + "' was not found in the RegisteredClientRepository.");
        }
        OAuth2Authorization.Builder builder =
            getOauth2AuthorizationBuilder(entity, registeredClient);
        LOGGER.debug("## toObject - END");
        return builder.build();
    }

    /**
     * This method is used to build an OAuth2Authorization object from an Authorization entity.
     * It retrieves the RegisteredClient associated with the Authorization entity and checks if it exists.
     * If the RegisteredClient does not exist, it throws a DataRetrievalFailureException.
     * It then builds an OAuth2Authorization object with the attributes from the Authorization entity.
     *
     * @param entity the Authorization entity to convert
     * @param registeredClient the RegisteredClient associated with the Authorization entity
     * @return a Builder for an OAuth2Authorization object with the attributes from the Authorization entity
     */
    private OAuth2Authorization.Builder getOauth2AuthorizationBuilder(Authorization entity,
                                                                      RegisteredClient registeredClient) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .id(entity.getId()).principalName(entity.getPrincipalName())
            .authorizationGrantType(resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))
            .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()))
            .attributes(attributes -> attributes.putAll(parseMap(this.objectMapper, entity.getAttributes())));
        if (entity.getState() != null) {
            builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
        }
        if (entity.getAuthorizationCodeValue() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                entity.getAuthorizationCodeValue(), entity.getAuthorizationCodeIssuedAt(),
                entity.getAuthorizationCodeExpiresAt());
            builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(this.objectMapper,
                entity.getAuthorizationCodeMetadata())));
        }
        if (entity.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, entity.getAccessTokenValue(), entity.getAccessTokenIssuedAt(),
                entity.getAccessTokenExpiresAt(),
                StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes()));
            builder.token(accessToken, metadata -> metadata.putAll(parseMap(this.objectMapper,
                entity.getAccessTokenMetadata())));
        }
        if (entity.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                entity.getRefreshTokenValue(), entity.getRefreshTokenIssuedAt(), entity.getRefreshTokenExpiresAt());
            builder.token(refreshToken, metadata -> metadata.putAll(parseMap(this.objectMapper,
                entity.getRefreshTokenMetadata())));
        }
        if (entity.getOidcIdTokenValue() != null) {
            OidcIdToken idToken = new OidcIdToken(
                entity.getOidcIdTokenValue(), entity.getOidcIdTokenIssuedAt(), entity.getOidcIdTokenExpiresAt(),
                parseMap(this.objectMapper, entity.getOidcIdTokenClaims()));
            builder.token(idToken, metadata -> metadata.putAll(parseMap(this.objectMapper,
                entity.getOidcIdTokenMetadata())));
        }
        if (entity.getUserCodeValue() != null) {
            OAuth2UserCode userCode = new OAuth2UserCode(
                entity.getUserCodeValue(), entity.getUserCodeIssuedAt(), entity.getUserCodeExpiresAt());
            builder.token(userCode, metadata -> metadata.putAll(parseMap(this.objectMapper,
                entity.getUserCodeMetadata())));
        }
        if (entity.getDeviceCodeValue() != null) {
            OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
                entity.getDeviceCodeValue(), entity.getDeviceCodeIssuedAt(), entity.getDeviceCodeExpiresAt());
            builder.token(deviceCode, metadata -> metadata.putAll(parseMap(this.objectMapper,
                entity.getDeviceCodeMetadata())));
        }
        return builder;
    }

    /**
     * This method is used to convert an OAuth2Authorization object into an Authorization entity.
     * It sets the attributes of the Authorization entity based on the attributes of the OAuth2Authorization object.
     * It handles the conversion of different types of OAuth2Tokens (like OAuth2AccessToken, OAuth2RefreshToken, etc.)
     * present in the OAuth2Authorization object.
     * It also handles the conversion of token metadata and claims.
     *
     * @param authorization the OAuth2Authorization object to convert
     * @return the converted Authorization entity
     */
    private Authorization toEntity(OAuth2Authorization authorization) {
        LOGGER.debug("## toEntity - START");
        Authorization entity = new Authorization();
        entity.setId(authorization.getId());
        entity.setRegisteredClientId(authorization.getRegisteredClientId());
        entity.setPrincipalName(authorization.getPrincipalName());
        entity.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
        entity.setAuthorizedScopes(StringUtils.collectionToDelimitedString(authorization.getAuthorizedScopes(),
            ","));
        entity.setAttributes(writeMap(this.objectMapper, authorization.getAttributes()));
        entity.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));

        setAuthCodeValues(authorization, entity);

        setAccessTokenValues(authorization, entity);

        setRefreshTokenValues(authorization, entity);

        setOidcTokenValues(authorization, entity);

        setUserCodeValues(authorization, entity);

        setDeviceCodeValues(authorization, entity);
        LOGGER.debug("## toEntity - END");
        return entity;
    }

    /**
     * This method is used to set the values of an OAuth2DeviceCode token into an Authorization entity.
     * It checks if the OAuth2DeviceCode token exists in the provided OAuth2Authorization object.
     * If it exists, it sets the token value, issued at timestamp, expires at timestamp, and metadata of the token into
     * the Authorization entity.
     *
     * @param authorization the OAuth2Authorization object that contains the OAuth2DeviceCode token
     * @param entity the Authorization entity to set the values into
     */
    private void setDeviceCodeValues(OAuth2Authorization authorization, Authorization entity) {
        OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode = authorization.getToken(OAuth2DeviceCode.class);
        if (deviceCode != null) {
            setTokenValues(
                deviceCode,
                entity::setDeviceCodeValue,
                entity::setDeviceCodeIssuedAt,
                entity::setDeviceCodeExpiresAt,
                entity::setDeviceCodeMetadata
            );
        }
    }

    /**
     * This method is used to set the values of an OAuth2UserCode token into an Authorization entity.
     * It checks if the OAuth2UserCode token exists in the provided OAuth2Authorization object.
     * If it exists, it sets the token value, issued at timestamp, expires at timestamp, and metadata of the token into
     * the Authorization entity.
     *
     * @param authorization the OAuth2Authorization object that contains the OAuth2UserCode token
     * @param entity the Authorization entity to set the values into
     */
    private void setUserCodeValues(OAuth2Authorization authorization, Authorization entity) {
        OAuth2Authorization.Token<OAuth2UserCode> userCode = authorization.getToken(OAuth2UserCode.class);
        if (userCode != null) {
            setTokenValues(
                userCode,
                entity::setUserCodeValue,
                entity::setUserCodeIssuedAt,
                entity::setUserCodeExpiresAt,
                entity::setUserCodeMetadata
            );
        }
    }

    /**
     * This method is used to set the values of an OidcIdToken token into an Authorization entity.
     * It checks if the OidcIdToken token exists in the provided OAuth2Authorization object.
     * If it exists, it sets the token value, issued at timestamp, expires at timestamp, and metadata of the token into
     * the Authorization entity. It also sets the claims of the OidcIdToken into the Authorization entity.
     *
     * @param authorization the OAuth2Authorization object that contains the OidcIdToken token
     * @param entity the Authorization entity to set the values into
     */
    private void setOidcTokenValues(OAuth2Authorization authorization, Authorization entity) {
        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);
        if (oidcIdToken != null) {
            setTokenValues(
                oidcIdToken,
                entity::setOidcIdTokenValue,
                entity::setOidcIdTokenIssuedAt,
                entity::setOidcIdTokenExpiresAt,
                entity::setOidcIdTokenMetadata
            );
            entity.setOidcIdTokenClaims(writeMap(this.objectMapper, oidcIdToken.getClaims()));
        }
    }

    /**
     * This method is used to set the values of an OAuth2RefreshToken token into an Authorization entity.
     * It checks if the OAuth2RefreshToken token exists in the provided OAuth2Authorization object.
     * If it exists, it sets the token value, issued at timestamp, expires at timestamp, and metadata of the token into
     * the Authorization entity.
     *
     * @param authorization the OAuth2Authorization object that contains the OAuth2RefreshToken token
     * @param entity the Authorization entity to set the values into
     */
    private void setRefreshTokenValues(OAuth2Authorization authorization, Authorization entity) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getToken(OAuth2RefreshToken.class);
        if (refreshToken != null) {
            setTokenValues(
                refreshToken,
                entity::setRefreshTokenValue,
                entity::setRefreshTokenIssuedAt,
                entity::setRefreshTokenExpiresAt,
                entity::setRefreshTokenMetadata
            );
        }
    }

    /**
     * This method is used to set the values of an OAuth2AccessToken token into an Authorization entity.
     * It checks if the OAuth2AccessToken token exists in the provided OAuth2Authorization object.
     * If it exists, it sets the token value, issued at timestamp, expires at timestamp, and metadata of the token into
     * the Authorization entity. It also sets the scopes of the OAuth2AccessToken into the Authorization entity.
     *
     * @param authorization the OAuth2Authorization object that contains the OAuth2AccessToken token
     * @param entity the Authorization entity to set the values into
     */
    private void setAccessTokenValues(OAuth2Authorization authorization, Authorization entity) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        if (accessToken != null) {
            setTokenValues(
                accessToken,
                entity::setAccessTokenValue,
                entity::setAccessTokenIssuedAt,
                entity::setAccessTokenExpiresAt,
                entity::setAccessTokenMetadata
            );
            if (accessToken.getToken().getScopes() != null) {
                entity.setAccessTokenScopes(StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(),
                    ","));
            }
        }
    }

    /**
     * This method is used to set the values of an OAuth2AuthorizationCode token into an Authorization entity.
     * It checks if the OAuth2AuthorizationCode token exists in the provided OAuth2Authorization object.
     * If it exists, it sets the token value, issued at timestamp, expires at timestamp, and metadata of the token into
     * the Authorization entity.
     *
     * @param authorization the OAuth2Authorization object that contains the OAuth2AuthorizationCode token
     * @param entity the Authorization entity to set the values into
     */
    private void setAuthCodeValues(OAuth2Authorization authorization, Authorization entity) {
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
            authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            setTokenValues(
                authorizationCode,
                entity::setAuthorizationCodeValue,
                entity::setAuthorizationCodeIssuedAt,
                entity::setAuthorizationCodeExpiresAt,
                entity::setAuthorizationCodeMetadata
            );
        }
    }

    /**
     * This method is used to set the values of a generic OAuth2Token into an Authorization entity.
     * It checks if the OAuth2Token exists in the provided OAuth2Authorization object.
     * If it exists, it sets the token value, issued at timestamp, expires at timestamp, and metadata of the token into
     * the Authorization entity.
     *
     * @param token the OAuth2Token to set the values from
     * @param tokenValueConsumer a Consumer to set the token value into the Authorization entity
     * @param issuedAtConsumer a Consumer to set the issued at timestamp into the Authorization entity
     * @param expiresAtConsumer a Consumer to set the expires at timestamp into the Authorization entity
     * @param metadataConsumer a Consumer to set the metadata into the Authorization entity
     */
    private void setTokenValues(
        OAuth2Authorization.Token<?> token,
        Consumer<String> tokenValueConsumer,
        Consumer<Instant> issuedAtConsumer,
        Consumer<Instant> expiresAtConsumer,
        Consumer<String> metadataConsumer) {
        LOGGER.debug("## setTokenValues - START");
        if (token != null) {
            LOGGER.debug("## setTokenValues - {}", "Token is not null");
            OAuth2Token oauth2Token = token.getToken();
            tokenValueConsumer.accept(oauth2Token.getTokenValue());
            issuedAtConsumer.accept(oauth2Token.getIssuedAt());
            expiresAtConsumer.accept(oauth2Token.getExpiresAt());
            metadataConsumer.accept(writeMap(this.objectMapper, token.getMetadata()));
        }
        LOGGER.debug("## setTokenValues - END");
    }

    /**
     * This method is used to resolve the type of an authorization grant from a string representation.
     * It checks if the provided string matches any of the predefined authorization grant types (like
     * AUTHORIZATION_CODE, CLIENT_CREDENTIALS, REFRESH_TOKEN, DEVICE_CODE). If it matches, it returns the corresponding
     * AuthorizationGrantType.
     * If it does not match any predefined types, it returns a new AuthorizationGrantType with the provided string as
     * its value.
     *
     * @param authorizationGrantType the string representation of the authorization grant type
     * @return the resolved AuthorizationGrantType
     */
    private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        } else if (AuthorizationGrantType.DEVICE_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.DEVICE_CODE;
        }
        return new AuthorizationGrantType(authorizationGrantType);              // Custom authorization grant type
    }
    
    
    /**
     * This method is used to hash the token and response with hashed and base64 encoded value.
     *
     * @param token the string representation of the authorization grant type
     * @return the hashed token
     */
    private String hashToken(String token) {
        return TokenHashingUtil.hashToken(token, tokenHashAlgorithm, tokenHashSalt);
    }
    
    
    /**
     * This method is used to update the hash token with plain text token 
     * so that internal process can use the token.
     *
     * @param authorization response object.
     * @param token Plain text of the token.
     * @param hashToken to compare the response object.
     */
    private void updateTokenWithHashToken(Authorization authorization, String token, String hashToken) {
        
        if (hashToken.equalsIgnoreCase(authorization.getAccessTokenValue())) {
            authorization.setAccessTokenValue(token);
        }
        if (hashToken.equalsIgnoreCase(authorization.getRefreshTokenValue())) {
            authorization.setRefreshTokenValue(token);
        }
        if (hashToken.equalsIgnoreCase(authorization.getOidcIdTokenValue())) {
            authorization.setOidcIdTokenValue(token);
        }
        
    }

    /**
     * Logs authorization failure audit events.
     *
     * @param eventType the authorization failure event type
     * @param username the username (may be null for client credentials)
     * @param clientId the client ID (may be null for user tokens)
     */
    private void logAuthorizationFailure(AuditEventType eventType, String username, String clientId) {
        try {
            // Determine actor information - either username or clientId
            String actorId = username != null ? username : clientId;
            String actorType = username != null ? "USER" : "CLIENT";
            
            UserActorContext actorContext = UserActorContext.builder()
                .userId(actorId)
                .username(username)
                .build();
            
            auditLogger.log(
                eventType.getType(),
                COMPONENT_NAME,
                AuditEventResult.FAILURE,
                eventType.getDescription(),
                actorContext,
                null  // RequestContext - not available in service layer
            );
            
            LOGGER.debug("Audit log created for {}: actorId={}, actorType={}", 
                eventType, actorId, actorType);
        } catch (Exception e) {
            LOGGER.error("Failed to create audit log for {}: {}", eventType, e.getMessage(), e);
        }
    }

    /**
     * Enriches the OAuth2Authorization with browser details from the authentication context.
     * Captures user-agent, IP address, language preferences, and other browser metadata
     * from CustomWebAuthenticationDetails if available.
     *
     * @param authorization the original OAuth2Authorization
     * @return enriched OAuth2Authorization with browser details in access token metadata and attributes
     */
    private OAuth2Authorization enrichAuthorizationWithBrowserDetails(OAuth2Authorization authorization) {
        try {
            // First, check if browser_details already exist in attributes
            // This happens during token exchange when the authorization already has browser details from login
            Object existingBrowserDetails = authorization.getAttribute("browser_details");
            
            if (existingBrowserDetails != null) {
                LOGGER.debug("## Browser details already exist in authorization, preserving them");
                // Browser details already captured during authentication, now add to access token metadata
                if (existingBrowserDetails instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> browserDetailsMap = (Map<String, Object>) existingBrowserDetails;
                    return addBrowserDetailsToAccessTokenFromMap(authorization, browserDetailsMap);
                }
                return authorization;
            }
            
            // No existing browser details, try to capture them
            CustomWebAuthenticationDetails details = extractCustomWebAuthenticationDetails(authorization);
            
            if (details != null) {
                LOGGER.debug("## Capturing new browser details from authentication");
                // Add browser details to authorization attributes
                OAuth2Authorization enrichedAuth = addBrowserDetailsToAttributes(authorization, details);
                
                // Also add browser details to access token metadata (if token exists)
                enrichedAuth = addBrowserDetailsToAccessToken(enrichedAuth, details);
                
                return enrichedAuth;
            } else {
                LOGGER.debug("## No CustomWebAuthenticationDetails found for capturing");
            }
        } catch (Exception e) {
            LOGGER.error("## Failed to enrich authorization with browser details: {}", e.getMessage(), e);
        }
        
        // Return original authorization if enrichment fails or details not available
        return authorization;
    }

    /**
     * Extracts CustomWebAuthenticationDetails from SecurityContext or authorization principal.
     * Prioritizes the authorization's principal attribute (from authentication step) over
     * the current security context to preserve browser details from the actual login.
     *
     * @param authorization the OAuth2Authorization to extract details from
     * @return CustomWebAuthenticationDetails if found, null otherwise
     */
    private CustomWebAuthenticationDetails extractCustomWebAuthenticationDetails(
            OAuth2Authorization authorization) {
        // First priority: try to get from the authorization's principal attribute
        // This contains the details from the actual authentication/login step
        CustomWebAuthenticationDetails details = extractDetailsFromAuthorizationPrincipal(authorization);
        if (details != null) {
            LOGGER.debug("## Found CustomWebAuthenticationDetails from authorization principal");
            return details;
        }
        
        // Second priority: try to get authentication from current security context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getDetails() instanceof CustomWebAuthenticationDetails) {
            LOGGER.debug("## Found CustomWebAuthenticationDetails from security context");
            return (CustomWebAuthenticationDetails) authentication.getDetails();
        }
        
        // Last resort: create from current HTTP request context
        // This may capture the wrong user agent (e.g., Postman during token exchange)
        LOGGER.debug("## Attempting to create CustomWebAuthenticationDetails from current request");
        return extractDetailsFromCurrentRequest();
    }

    /**
     * Extracts CustomWebAuthenticationDetails from the authorization's principal attribute.
     *
     * @param authorization the OAuth2Authorization to extract details from
     * @return CustomWebAuthenticationDetails if found, null otherwise
     */
    private CustomWebAuthenticationDetails extractDetailsFromAuthorizationPrincipal(
            OAuth2Authorization authorization) {
        Object principal = authorization.getAttribute("java.security.Principal");
        
        if (principal instanceof Authentication) {
            Authentication principalAuth = (Authentication) principal;
            Object principalDetails = principalAuth.getDetails();
            
            if (principalDetails instanceof CustomWebAuthenticationDetails) {
                return (CustomWebAuthenticationDetails) principalDetails;
            }
        }
        return null;
    }

    /**
     * Extracts CustomWebAuthenticationDetails from the current HTTP request context.
     * This is a fallback for existing sessions where the authentication object
     * was created before the custom details source was configured.
     *
     * @return CustomWebAuthenticationDetails created from current request, or null if not available
     */
    private CustomWebAuthenticationDetails extractDetailsFromCurrentRequest() {
        try {
            ServletRequestAttributes attributes = 
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            if (attributes != null) {
                jakarta.servlet.http.HttpServletRequest request = attributes.getRequest();
                CustomWebAuthenticationDetailsSource detailsSource = 
                    new CustomWebAuthenticationDetailsSource();
                return detailsSource.buildDetails(request);
            }
        } catch (IllegalStateException e) {
            LOGGER.debug("## No HTTP request context available: {}", e.getMessage());
        } catch (Exception e) {
            LOGGER.warn("## Failed to extract details from current request: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Adds browser details from an existing map to the access token metadata.
     * Used when browser details were already captured during authentication
     * and need to be applied to the access token during token generation.
     *
     * @param authorization the OAuth2Authorization
     * @param browserDetailsMap the map containing browser details
     * @return enriched OAuth2Authorization with browser details in access token metadata
     */
    private OAuth2Authorization addBrowserDetailsToAccessTokenFromMap(
            OAuth2Authorization authorization, Map<String, Object> browserDetailsMap) {
        
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
        
        if (accessToken == null) {
            LOGGER.debug("## Access token is null, skipping token metadata enrichment");
            return authorization;
        }
        
        // Create new metadata map with browser details
        Map<String, Object> metadata = new LinkedHashMap<>(accessToken.getMetadata());
        Object userAgent = browserDetailsMap.get(USER_AGENT_KEY);
        metadata.put(USER_AGENT_KEY, userAgent != null ? userAgent : UNKNOWN);
        Object ipAddress = browserDetailsMap.get(IP_ADDRESS_KEY);
        metadata.put(IP_ADDRESS_KEY, ipAddress != null ? ipAddress : UNKNOWN);
        Object acceptLanguage = browserDetailsMap.get(ACCEPT_LANGUAGE_KEY);
        metadata.put(ACCEPT_LANGUAGE_KEY, acceptLanguage != null ? acceptLanguage : UNKNOWN);
        Object referer = browserDetailsMap.get(REFERER_KEY);
        metadata.put(REFERER_KEY, referer != null ? referer : UNKNOWN);
        Object sessionId = browserDetailsMap.get(SESSION_ID_KEY);
        metadata.put(SESSION_ID_KEY, sessionId != null ? sessionId : UNKNOWN);
        Object capturedAt = browserDetailsMap.get(CAPTURED_AT_KEY);
        metadata.put(CAPTURED_AT_KEY, capturedAt != null ? capturedAt : Instant.now().toString());
        
        // Rebuild authorization with updated access token metadata
        OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);
        builder.token(accessToken.getToken(), meta -> {
            meta.clear();
            meta.putAll(metadata);
        });
        
        return builder.build();
    }

    /**
     * Adds browser details to the access token metadata.
     *
     * @param authorization the OAuth2Authorization
     * @param details the CustomWebAuthenticationDetails containing browser information
     * @return enriched OAuth2Authorization with browser details in access token metadata
     */
    private OAuth2Authorization addBrowserDetailsToAccessToken(
            OAuth2Authorization authorization, CustomWebAuthenticationDetails details) {
        
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
        
        if (accessToken == null) {
            LOGGER.debug("## Access token is null, skipping token metadata enrichment");
            return authorization;
        }
        
        // Create new metadata map with browser details
        Map<String, Object> metadata = new LinkedHashMap<>(accessToken.getMetadata());
        metadata.put(USER_AGENT_KEY, details.getUserAgent() != null ? details.getUserAgent() : UNKNOWN);
        metadata.put(IP_ADDRESS_KEY, details.getRemoteAddress());
        metadata.put(ACCEPT_LANGUAGE_KEY, 
            details.getAcceptLanguage() != null ? details.getAcceptLanguage() : UNKNOWN);
        metadata.put(REFERER_KEY, details.getReferer() != null ? details.getReferer() : UNKNOWN);
        metadata.put(SESSION_ID_KEY, 
            details.getSessionId() != null ? details.getSessionId() : UNKNOWN);
        metadata.put(CAPTURED_AT_KEY, Instant.now().toString());
        
        // Rebuild authorization with updated access token metadata
        OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);
        builder.token(accessToken.getToken(), meta -> {
            meta.clear();
            meta.putAll(metadata);
        });
        
        return builder.build();
    }

    /**
     * Adds browser details to the authorization attributes.
     * This makes browser information available throughout the OAuth2 flow,
     * not just in the access token metadata.
     *
     * @param authorization the OAuth2Authorization
     * @param details the CustomWebAuthenticationDetails containing browser information
     * @return enriched OAuth2Authorization with browser details in attributes
     */
    private OAuth2Authorization addBrowserDetailsToAttributes(
            OAuth2Authorization authorization, CustomWebAuthenticationDetails details) {
        
        try {
            // Create a map with browser details
            Map<String, Object> browserDetailsMap = new LinkedHashMap<>();
            browserDetailsMap.put(USER_AGENT_KEY, details.getUserAgent() != null ? details.getUserAgent() : UNKNOWN);
            browserDetailsMap.put(IP_ADDRESS_KEY, details.getRemoteAddress());
            browserDetailsMap.put(ACCEPT_LANGUAGE_KEY, 
                details.getAcceptLanguage() != null ? details.getAcceptLanguage() : UNKNOWN);
            browserDetailsMap.put(REFERER_KEY, details.getReferer() != null ? details.getReferer() : UNKNOWN);
            browserDetailsMap.put(SESSION_ID_KEY, 
                details.getSessionId() != null ? details.getSessionId() : UNKNOWN);
            browserDetailsMap.put(CAPTURED_AT_KEY, Instant.now().toString());
            
            // Rebuild authorization with browser details attribute
            OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);
            builder.attribute("browser_details", browserDetailsMap);
            
            return builder.build();
        } catch (Exception e) {
            LOGGER.error("## Failed to add browser details to attributes: {}", e.getMessage(), e);
            return authorization;
        }
    }

}
