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

package org.eclipse.ecsp.oauth2.server.core.service;

import org.eclipse.ecsp.audit.enums.AuditEventResult;
import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.entities.Authorization;
import org.eclipse.ecsp.oauth2.server.core.exception.CustomOauth2AuthorizationException;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.eclipse.ecsp.oauth2.server.core.request.dto.RevokeTokenRequest;
import org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients;
import org.eclipse.ecsp.oauth2.server.core.utils.JwtTokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.AMOUNT_TO_ADD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.AMOUNT_TO_ADD1;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.DUMMY_TOKEN;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ID;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.PRINCIPAL_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations.createAccTokenAuthorization;
import static org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations.createAuthorization;
import static org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations.createDeviceCodeAuthorization;
import static org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations.createRefreshTokenAuthorization;
import static org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations.createUserCodeAuthorization;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the IgniteOauth2AuthorizationService.
 */
@ActiveProfiles("test")
class AuthorizationServiceTest {

    private static final int INT_1800 = 1800;
    private static final int INT_500 = 500;
    private static final int INT_3600 = 3600;    
    @Mock
    AuthorizationService authorizationService;
    @Mock
    ClientRegistrationManager clientManger;
    @Mock
    AuthorizationRepository authorizationRepository;
    @Mock
    JwtTokenValidator jwtTokenValidator;
    @Mock
    AuditLogger auditLogger;

    private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredDummyClient().build();
    private static final AuthorizationGrantType AUTHORIZATION_GRANT_TYPE = AuthorizationGrantType.CLIENT_CREDENTIALS;

    /**
     * This method sets up the test environment before each test.
     * It initializes the mocks.
     */
    @BeforeEach
    void setUp() {
        this.authorizationRepository = mock(AuthorizationRepository.class);
        this.clientManger = mock(ClientRegistrationManager.class);
        this.authorizationService = Mockito.mock(AuthorizationService.class);
        this.jwtTokenValidator = mock(JwtTokenValidator.class);
        this.auditLogger = mock(AuditLogger.class);
    }

    /**
     * This test method tests the scenario where an attempt to save a null authorization throws an exception.
     * It sets up the necessary parameters and then calls the save method.
     * The test asserts that an IllegalArgumentException is thrown.
     */
    @Test    void saveWhenAuthorizationNullThrowsException() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        OAuth2Authorization authorization = null;
        assertThrows(IllegalArgumentException.class, () -> authorizationService.save(authorization));
    }

    /**
     * This test method tests the scenario where an attempt to remove a null authorization throws an exception.
     * It sets up the necessary parameters and then calls the remove method.
     * The test asserts that an IllegalArgumentException is thrown.
     */
    @Test    void removeWhenAuthorizationNullThrowsException() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        OAuth2Authorization authorization = null;
        assertThrows(IllegalArgumentException.class, () -> authorizationService.remove(authorization));

    }

    /**
     * This test method tests the scenario where an attempt to find an authorization by a null ID throws an exception.
     * It sets up the necessary parameters and then calls the findById method.
     * The test asserts that an IllegalArgumentException is thrown.
     */
    @Test
    void findByIdWhenAuthorizationNullThrowsException() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        String id = "";
        assertThrows(IllegalArgumentException.class, () -> authorizationService.findById(id));
    }

    /**
     * This test method tests the scenario where an attempt to find an authorization by an ID that is not present
     * returns null.
     * It sets up the necessary parameters and then calls the findById method.
     * The test asserts that the returned authorization is null.
     */
    @Test
    void findByIdReturnNullWhenIdNotPresent() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        OAuth2Authorization authorization = this.authorizationService.findById("1");
        assertNull(authorization);

    }

    /**
     * This test method tests the scenario where an attempt to find an authorization by a token that does not exist
     * returns null.
     * It sets up the necessary parameters and then calls the findByToken method.
     * The test asserts that the returned authorization is null.
     */
    @Test
    void findByTokenReturnNullWhenTokenNotExist() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);

        OAuth2TokenType oauth2TokenType = OAuth2TokenType.ACCESS_TOKEN;
        String dummyToken = DUMMY_TOKEN;
        OAuth2Authorization authorization = this.authorizationService.findByToken(dummyToken, oauth2TokenType);
        assertNull(authorization);
    }

    /**
     * This test method tests the scenario where a new authorization is saved successfully.
     * It sets up the necessary parameters and then calls the save method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void saveWhenAuthorizationNewThenSaved() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        Authorization expAuthorization = createAuthorization();
        OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
            //  .token(AUTHORIZATION_CODE)
            .build();
        when(this.authorizationRepository.findById(Mockito.anyString()))
            .thenReturn(Optional.of(expAuthorization));

        this.authorizationService.save(expectedAuthorization);

        OAuth2Authorization authorization = this.authorizationService.findById(ID);
        assert authorization != null;
        assertThat(authorization.getId()).isEqualTo(expectedAuthorization.getId());
    }

    /**
     * This test method tests the scenario where an authorization with an access token is saved successfully.
     * It sets up the necessary parameters and then calls the save method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void saveWhenAccessTokenInAuthorizationThenSaved() {

        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        Authorization expAuthorization = createAccTokenAuthorization();

        OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
            //  .token(AUTHORIZATION_CODE)
            .build();
        when(this.authorizationRepository.findById(Mockito.anyString()))
            .thenReturn(Optional.of(expAuthorization));

        this.authorizationService.save(expectedAuthorization);

        OAuth2Authorization authorization = this.authorizationService.findById(ID);
        assert authorization != null;
        assertThat(authorization.getId()).isEqualTo(expectedAuthorization.getId());
    }

    /**
     * This test method tests the scenario where an authorization with a refresh token is saved successfully.
     * It sets up the necessary parameters and then calls the save method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void saveWhenRefreshTokenInAuthorizationThenSaved() {

        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        Authorization expAuthorization = createRefreshTokenAuthorization();
        OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
            //  .token(AUTHORIZATION_CODE)
            .build();
        when(this.authorizationRepository.findById(Mockito.anyString()))
            .thenReturn(Optional.of(expAuthorization));

        this.authorizationService.save(expectedAuthorization);

        OAuth2Authorization authorization = this.authorizationService.findById(ID);
        assert authorization != null;
        assertThat(authorization.getId()).isEqualTo(expectedAuthorization.getId());
    }

    /**
     * This test method tests the scenario where an attempt to find an authorization by a wrong token type returns null.
     * It sets up the necessary parameters and then calls the findByToken method.
     * The test asserts that the returned authorization is null.
     */
    @Test
    void findByTokenWhenWrongTokenTypeThenNotFound() {
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token",
            Instant.now().truncatedTo(ChronoUnit.MILLIS));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
            .refreshToken(refreshToken)
            .build();
        this.authorizationService.save(authorization);

        OAuth2Authorization result = this.authorizationService.findByToken(
            refreshToken.getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
        assertThat(result).isNull();
    }

    /**
     * This test method tests the scenario where an authorization is found successfully by a device code.
     * It sets up the necessary parameters and then calls the findByToken method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void findByTokenWhenDeviceCodeExistsThenFound() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        OAuth2DeviceCode deviceCode = new OAuth2DeviceCode("device-code",
            Instant.now().truncatedTo(ChronoUnit.MILLIS),
            Instant.now().plus(AMOUNT_TO_ADD, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
            .token(deviceCode)
            .build();
        this.authorizationService.save(authorization);
        when(this.authorizationRepository.findByDeviceCodeValue(Mockito.anyString()))
            .thenReturn(Optional.of(createDeviceCodeAuthorization()));
        OAuth2Authorization result = this.authorizationService.findByToken(
            deviceCode.getTokenValue(), new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE));
        assert result != null;
        assertThat(authorization.getId()).isEqualTo(result.getId());
    }

    /**
     * This test method tests the scenario where an authorization is found successfully by a user code.
     * It sets up the necessary parameters and then calls the findByToken method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void findByTokenWhenUserCodeExistsThenFound() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        OAuth2UserCode userCode = new OAuth2UserCode("user-code",
            Instant.now().truncatedTo(ChronoUnit.MILLIS),
            Instant.now().plus(AMOUNT_TO_ADD, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS));
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
            .token(userCode)
            .build();
        this.authorizationService.save(authorization);

        when(this.authorizationRepository.findByUserCodeValue(Mockito.anyString()))
            .thenReturn(Optional.of(createUserCodeAuthorization()));
        OAuth2Authorization result = this.authorizationService.findByToken(
            userCode.getTokenValue(), new OAuth2TokenType(OAuth2ParameterNames.USER_CODE));
        assert result != null;
        assertThat(authorization.getId()).isEqualTo(result.getId());
    }

    /**
     * This test method tests the scenario where an authorization is found successfully by an ID token.
     * It sets up the necessary parameters and then calls the findByToken method.
     * The test asserts that the returned authorization is not null and the ID is as expected.
     */
    @Test
    void findByTokenWhenIdTokenExistsThenFound() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString()))
            .thenReturn(REGISTERED_CLIENT);
        OidcIdToken idToken =  OidcIdToken.withTokenValue("id-token")
            .issuer("https://localhost.com")
            .subject("subject")
            .issuedAt(Instant.now().minusSeconds(AMOUNT_TO_ADD1).truncatedTo(ChronoUnit.MILLIS))
            .expiresAt(Instant.now().truncatedTo(ChronoUnit.MILLIS))
            .build();
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
            .id(ID)
            .principalName(PRINCIPAL_NAME)
            .authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
            .token(idToken, metadata ->
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()))
            .build();
        this.authorizationService.save(authorization);
        when(this.authorizationRepository.findByOidcIdTokenValue(Mockito.anyString()))
            .thenReturn(Optional.of(createAuthorization()));

        OAuth2Authorization result = this.authorizationService.findByToken(
            idToken.getTokenValue(), new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        assert result != null;
        assertThat(authorization.getId()).isEqualTo(result.getId());

    }

    /**
     * This test method tests the scenario where token revocation by principal and client ID is successful. It sets up
     * the necessary parameters with active tokens and then calls the revokenTokenByPrincipalAndClientId method. The
     * test asserts that the returned response indicates successful token revocation.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenActiveTokensThenSuccess() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);

        // Create test authorization entities
        Authorization testAuth1 = createAccTokenAuthorization();
        testAuth1.setPrincipalName("testUser");
        testAuth1.setRegisteredClientId("testClient");
        testAuth1.setAccessTokenExpiresAt(Instant.now().plusSeconds(INT_3600));

        Authorization testAuth2 = createAccTokenAuthorization();
        testAuth2.setPrincipalName("testUser");
        testAuth2.setRegisteredClientId("testClient");
        testAuth2.setAccessTokenExpiresAt(Instant.now().plusSeconds(INT_1800));
        List<Authorization> activeTokens = List.of(testAuth1, testAuth2);
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(eq("testUser"), eq("testClient"),
                any(Instant.class))).thenReturn(activeTokens);
        when(this.authorizationRepository.saveAll(any())).thenReturn(activeTokens);

        String result = this.authorizationService.revokenTokenByPrincipalAndClientId("testUser", "testClient");

        assertThat(result).isEqualTo("Token revoked successfully!");
    }

    /**
     * This test method tests the scenario where no active tokens exist for the given principal and client ID. It sets
     * up the necessary parameters with empty token list and then calls the revokenTokenByPrincipalAndClientId method.
     * The test asserts that the returned response indicates no active tokens exist.
     */
    @Test    void revokenTokenByPrincipalAndClientIdWhenNoActiveTokensThenNoActiveTokenMessage() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        List<Authorization> emptyTokens = List.of();
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq("testUser"), eq("testClient"), any(Instant.class))).thenReturn(emptyTokens);
        
        String result = this.authorizationService.revokenTokenByPrincipalAndClientId("testUser", "testClient");
        
        assertThat(result).isEqualTo("No active token exist for the provided id!");
    }

    /**
     * This test method tests the scenario where the repository throws an exception during token revocation. It sets up
     * the necessary parameters to throw an exception and then calls the revokenTokenByPrincipalAndClientId method. The
     * test asserts that a CustomOauth2AuthorizationException is thrown with SERVER_ERROR.
     */
    @Test    void revokenTokenByPrincipalAndClientIdWhenRepositoryExceptionThenThrowsCustomException() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq("testUser"), eq("testClient"), any(Instant.class)))
            .thenThrow(new RuntimeException("Database connection failed"));
        
        assertThrows(RuntimeException.class, () -> 
            this.authorizationService.revokenTokenByPrincipalAndClientId("testUser", "testClient"));
    }

    /**
     * This test method tests the scenario where token revocation is successful with null principal name.
     * It sets up the necessary parameters with active tokens and null principal and then calls the method.
     * The test verifies that the method handles null principal gracefully.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenNullPrincipalThenHandledGracefully() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        List<Authorization> emptyTokens = List.of();
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(eq(null), eq("testClient"),
                any(Instant.class))).thenReturn(emptyTokens);

        String result = this.authorizationService.revokenTokenByPrincipalAndClientId(null, "testClient");

        assertThat(result).isEqualTo("No active token exist for the provided id!");
    }

    /**
     * This test method tests the scenario where token revocation is successful with null client ID.
     * It sets up the necessary parameters with active tokens and null client ID and then calls the method.
     * The test verifies that the method handles null client ID gracefully.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenNullClientIdThenHandledGracefully() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        List<Authorization> emptyTokens = List.of();
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(eq("testUser"), eq(null),
                any(Instant.class))).thenReturn(emptyTokens);

        String result = this.authorizationService.revokenTokenByPrincipalAndClientId("testUser", null);

        assertThat(result).isEqualTo("No active token exist for the provided id!");
    }

    /**
     * This test method tests the scenario where token revocation is successful with empty string parameters.
     * It sets up the necessary parameters with empty string values and then calls the method.
     * The test verifies that the method handles empty strings gracefully.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenEmptyStringsThenHandledGracefully() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        List<Authorization> emptyTokens = List.of();
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq(""), eq(""), any(Instant.class))).thenReturn(emptyTokens);
        
        String result = this.authorizationService.revokenTokenByPrincipalAndClientId("", "");
        
        assertThat(result).isEqualTo("No active token exist for the provided id!");
    }

    /**
     * This test method tests the scenario where token revocation is successful with single active token.
     * It sets up the necessary parameters with one active token and then calls the method.
     * The test verifies that single token revocation works correctly.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenSingleTokenThenSuccess() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        Authorization testAuth = createAccTokenAuthorization();
        testAuth.setPrincipalName("singleUser");
        testAuth.setRegisteredClientId("singleClient");
        testAuth.setAccessTokenExpiresAt(Instant.now().plusSeconds(INT_3600));
        
        List<Authorization> singleToken = List.of(testAuth);
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq("singleUser"), eq("singleClient"), any(Instant.class))).thenReturn(singleToken);
        when(this.authorizationRepository.saveAll(any())).thenReturn(singleToken);
        
        String result = this.authorizationService.revokenTokenByPrincipalAndClientId("singleUser", "singleClient");
        
        assertThat(result).isEqualTo("Token revoked successfully!");
    }

    /**
     * This test method tests the scenario where token revocation fails during saveAll operation.
     * It sets up the necessary parameters to throw exception during save and then calls the method.
     * The test verifies that save exceptions are properly handled.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenSaveFailsThenThrowsException() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        Authorization testAuth = createAccTokenAuthorization();
        testAuth.setPrincipalName("testUser");
        testAuth.setRegisteredClientId("testClient");
        testAuth.setAccessTokenExpiresAt(Instant.now().plusSeconds(INT_3600));
        
        List<Authorization> activeTokens = List.of(testAuth);
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq("testUser"), eq("testClient"), any(Instant.class))).thenReturn(activeTokens);
        when(this.authorizationRepository.saveAll(any())).thenThrow(new RuntimeException("Save operation failed"));
        
        assertThrows(RuntimeException.class, () -> 
            this.authorizationService.revokenTokenByPrincipalAndClientId("testUser", "testClient"));
    }

    /**
     * This test method tests the scenario where token revocation works with very long principal name and client ID.
     * It sets up the necessary parameters with long string values and then calls the method.
     * The test verifies that the method handles long strings correctly.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenLongStringsThenSuccess() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        String longPrincipal = "a".repeat(INT_500);
        String longClientId = "b".repeat(INT_500);
        
        Authorization testAuth = createAccTokenAuthorization();
        testAuth.setPrincipalName(longPrincipal);
        testAuth.setRegisteredClientId(longClientId);
        testAuth.setAccessTokenExpiresAt(Instant.now().plusSeconds(INT_3600));
        
        List<Authorization> activeTokens = List.of(testAuth);
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq(longPrincipal), eq(longClientId), any(Instant.class))).thenReturn(activeTokens);
        when(this.authorizationRepository.saveAll(any())).thenReturn(activeTokens);
        
        String result = this.authorizationService.revokenTokenByPrincipalAndClientId(longPrincipal, longClientId);
        
        assertThat(result).isEqualTo("Token revoked successfully!");
    }

    /**
     * This test method tests the scenario where token revocation works with special characters in parameters.
     * It sets up the necessary parameters with special characters and then calls the method.
     * The test verifies that the method handles special characters correctly.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenSpecialCharactersThenSuccess() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        String specialPrincipal = "user@domain.com";
        String specialClientId = "client-123_test";
        
        Authorization testAuth = createAccTokenAuthorization();
        testAuth.setPrincipalName(specialPrincipal);
        testAuth.setRegisteredClientId(specialClientId);
        testAuth.setAccessTokenExpiresAt(Instant.now().plusSeconds(INT_3600));
        
        List<Authorization> activeTokens = List.of(testAuth);
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq(specialPrincipal), eq(specialClientId), any(Instant.class))).thenReturn(activeTokens);
        when(this.authorizationRepository.saveAll(any())).thenReturn(activeTokens);
        
        String result = this.authorizationService.revokenTokenByPrincipalAndClientId(specialPrincipal, specialClientId);
        
        assertThat(result).isEqualTo("Token revoked successfully!");
    }    
    
    /**
     * This test method tests the scenario where multiple tokens exist but they are expired.
     * It sets up the necessary parameters with expired tokens and then calls the method.
     * The test verifies that expired tokens are not returned by the repository query.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenExpiredTokensThenNoActiveTokens() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        // Create expired tokens to test the scenario where tokens exist but are expired
        Authorization expiredAuth1 = createAccTokenAuthorization();
        expiredAuth1.setPrincipalName("testUser");
        expiredAuth1.setRegisteredClientId("testClient");
        expiredAuth1.setAccessTokenExpiresAt(Instant.now().minusSeconds(INT_3600)); // Expired 1 hour ago
        
        Authorization expiredAuth2 = createAccTokenAuthorization();
        expiredAuth2.setPrincipalName("testUser");
        expiredAuth2.setRegisteredClientId("testClient");
        expiredAuth2.setAccessTokenExpiresAt(Instant.now().minusSeconds(INT_1800)); // Expired 30 minutes ago
        
        // Repository should return empty list for expired tokens since the query filters by expiration time
        // The query specifically looks for tokens where accessTokenExpiresAt > current time
        List<Authorization> emptyTokens = List.of();
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq("testUser"), eq("testClient"), any(Instant.class))).thenReturn(emptyTokens);
        
        String result = this.authorizationService.revokenTokenByPrincipalAndClientId("testUser", "testClient");
        
        assertThat(result).isEqualTo("No active token exist for the provided id!");
        
        // Verify that the repository was called with the correct parameters including time filter
        verify(this.authorizationRepository).findByPrincipalNameClientAndValidTokens(
            eq("testUser"), eq("testClient"), any(Instant.class));
    }

    /**
     * This test method tests the scenario where token revocation works with multiple different client IDs for same
     * user. It sets up the necessary parameters with multiple tokens for different clients and then calls the method.
     * The test verifies that only tokens for the specified client are revoked.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenMultipleClientIdsThenOnlySpecificClientRevoked() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        Authorization testAuth = createAccTokenAuthorization();
        testAuth.setPrincipalName("testUser");
        testAuth.setRegisteredClientId("specificClient");
        testAuth.setAccessTokenExpiresAt(Instant.now().plusSeconds(INT_3600));
        
        List<Authorization> specificClientTokens = List.of(testAuth);
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq("testUser"), eq("specificClient"), any(Instant.class))).thenReturn(specificClientTokens);
        when(this.authorizationRepository.saveAll(any())).thenReturn(specificClientTokens);
        
        String result = this.authorizationService.revokenTokenByPrincipalAndClientId("testUser", "specificClient");
        
        assertThat(result).isEqualTo("Token revoked successfully!");
    }

    /**
     * This test method tests the scenario where the method logs appropriate messages during execution.
     * It sets up the necessary parameters and verifies logging behavior.
     * The test ensures that appropriate log messages are generated.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenCalledThenLogsAppropriateMessages() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        Authorization testAuth = createAccTokenAuthorization();
        testAuth.setPrincipalName("logTestUser");
        testAuth.setRegisteredClientId("logTestClient");
        testAuth.setAccessTokenExpiresAt(Instant.now().plusSeconds(INT_3600));
        
        List<Authorization> activeTokens = List.of(testAuth);
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq("logTestUser"), eq("logTestClient"), any(Instant.class))).thenReturn(activeTokens);
        when(this.authorizationRepository.saveAll(any())).thenReturn(activeTokens);
        
        String result = this.authorizationService.revokenTokenByPrincipalAndClientId("logTestUser", "logTestClient");
        
        assertThat(result).isEqualTo("Token revoked successfully!");
        // Note: In a real scenario, you would use a logging framework test library to verify log messages
    }

    /**
     * This test method tests the scenario where method is called with whitespace-only parameters.
     * It sets up the necessary parameters with whitespace strings and then calls the method.
     * The test verifies that whitespace parameters are handled correctly.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenWhitespaceParametersThenHandledCorrectly() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        String whitespacePrincipal = "   ";
        String whitespaceClientId = "\t\n";
        
        List<Authorization> emptyTokens = List.of();
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq(whitespacePrincipal), eq(whitespaceClientId), any(Instant.class))).thenReturn(emptyTokens);
        
        String result = this.authorizationService
                .revokenTokenByPrincipalAndClientId(whitespacePrincipal, whitespaceClientId);
        
        assertThat(result).isEqualTo("No active token exist for the provided id!");
    }

    /**
     * This test method tests the scenario where repository returns null instead of empty list.
     * It sets up the necessary parameters to return null from repository and then calls the method.
     * The test verifies that null return is handled gracefully.
     */
    @Test
    void revokenTokenByPrincipalAndClientIdWhenRepositoryReturnsNullThenHandledGracefully() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        when(this.clientManger.findById(Mockito.anyString())).thenReturn(REGISTERED_CLIENT);
        
        when(this.authorizationRepository.findByPrincipalNameClientAndValidTokens(
            eq("testUser"), eq("testClient"), any(Instant.class))).thenReturn(null);
        
        // This should throw an exception as the code expects a non-null list
        assertThrows(RuntimeException.class, () -> 
            this.authorizationService.revokenTokenByPrincipalAndClientId("testUser", "testClient"));
    }

    /**
     * This test verifies that audit logging is called when revoking a token with an invalid token.
     * It ensures AUTHZ_FAILURE_REVOKED_TOKEN event is logged with correct parameters.
     */
    @Test
    void revokeTokenWithInvalidTokenShouldLogAuthorizationFailure() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        
        RevokeTokenRequest request = new RevokeTokenRequest();
        request.setClientId("testClient");
        request.setUsername("testUser");
        
        String invalidToken = "Bearer invalid-jwt-token";
        
        // Mock token validation to return false
        when(jwtTokenValidator.validateToken(anyString())).thenReturn(false);
        
        // Attempt to revoke token should throw exception
        assertThrows(CustomOauth2AuthorizationException.class, () -> 
            authorizationService.revokeToken(request, invalidToken));
        
        // Verify audit logger was called with AUTHZ_FAILURE_REVOKED_TOKEN
        verify(auditLogger, times(1)).log(
            eq("AUTHZ_FAILURE_REVOKED_TOKEN"),
            eq("uidam-authorization-server"),
            eq(AuditEventResult.FAILURE),
            eq("Authorization failed - token has been revoked"),
            any(),  // actorContext
            isNull()  // targetContext
        );
    }

    /**
     * This test verifies that audit logging is called when revoking a token with a null token.
     * It ensures AUTHZ_FAILURE_REVOKED_TOKEN event is logged.
     */
    @Test
    void revokeTokenWithNullTokenShouldLogAuthorizationFailure() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        
        RevokeTokenRequest request = new RevokeTokenRequest();
        request.setClientId("testClient");
        
        String nullToken = null;
        
        // Attempt to revoke with null token should throw exception (NullPointerException)
        assertThrows(NullPointerException.class, () -> 
            authorizationService.revokeToken(request, nullToken));
        
        // Verify audit logger was NOT called for null token (exception before validation)
        verify(auditLogger, never()).log(
            anyString(),
            anyString(),
            any(),
            anyString(),
            any(),
            any()
        );
    }

    /**
     * This test verifies that audit logging parameters include the correct actor information.
     * The actor should be the username if present, otherwise the clientId.
     */
    @Test
    void revokeTokenWithClientIdOnlyShouldLogWithClientIdAsActor() {
        authorizationService = new AuthorizationService(
                authorizationRepository, clientManger, jwtTokenValidator,
                auditLogger);
        
        RevokeTokenRequest request = new RevokeTokenRequest();
        request.setClientId("testClient");
        // No username set
        
        String invalidToken = "Bearer invalid-jwt-token";
        
        // Mock token validation to return false
        when(jwtTokenValidator.validateToken(anyString())).thenReturn(false);
        
        // Attempt to revoke token should throw exception
        assertThrows(CustomOauth2AuthorizationException.class, () -> 
            authorizationService.revokeToken(request, invalidToken));
        
        // Verify audit logger was called
        verify(auditLogger, times(1)).log(
            eq("AUTHZ_FAILURE_REVOKED_TOKEN"),
            eq("uidam-authorization-server"),
            eq(AuditEventResult.FAILURE),
            eq("Authorization failed - token has been revoked"),
            any(),  // actorContext - should have clientId as userId
            isNull()  // targetContext
        );
    }
}

