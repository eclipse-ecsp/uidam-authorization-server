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

package org.eclipse.ecsp.oauth2.server.core.controller;

import io.prometheus.client.CollectorRegistry;
import org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants;
import org.eclipse.ecsp.oauth2.server.core.config.KeyStoreConfigByJavaKeyStore;
import org.eclipse.ecsp.oauth2.server.core.config.KeyStoreConfigByPubPvtKey;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.entities.Authorization;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.eclipse.ecsp.oauth2.server.core.service.ClientRegistrationManager;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.JwtTokenValidator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.ECSP;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_ALIAS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_FILENAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_PASS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.DUMMY_TOKEN;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.SECONDS_TO_ADD3;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TOKEN_METADATA;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the AuthorizationController.
 */
@ActiveProfiles("test") 
@TestPropertySource("classpath:application-test.properties") 
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT) 
@AutoConfigureWebTestClient(timeout = "3600000")
@ContextConfiguration(classes = {AuthorizationControllerTest.TestConfig.class})
class AuthorizationControllerTest {
    @MockitoBean
    AuthorizationRepository authorizationRepository;

    @MockitoBean
    JwtTokenValidator jwtTokenValidator;

    @MockitoBean
    ClientRegistrationManager clientRegistrationManager;

    @MockitoBean
    KeyStoreConfigByJavaKeyStore keyStoreConfigByJavaKeyStore;

    @MockitoBean
    KeyStoreConfigByPubPvtKey keyStoreConfigByPubPvtKey;

    @Autowired
    private WebTestClient webTestClient;

    /**
     * This method is executed before and after each test. It clears the default registry of the CollectorRegistry.
     */
    @BeforeEach 
    @AfterEach
    void cleanup() {
        CollectorRegistry.defaultRegistry.clear();
    }

    /**
     * This test method tests the scenario where the revoke token request is successful. It sets up the necessary
     * parameters and then calls the revoke token method. The test asserts that the returned status is HttpStatus.OK.
     */
    @Test
    void testRevokeToken() {
        Authorization auth = new Authorization();
        auth.setRegisteredClientId("testClient");
        auth.setPrincipalName("testClient");
        auth.setAuthorizationGrantType("client_credentials");
        auth.setAccessTokenMetadata(TOKEN_METADATA);

        auth.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        auth.setAccessTokenExpiresAt(Instant.now().plusSeconds(SECONDS_TO_ADD3));

        auth.setAccessTokenScopes("RevokeToken");
        auth.setAuthorizedScopes("RevokeToken");
        auth.setAccessTokenType(OAuth2TokenType.ACCESS_TOKEN.getValue());
        auth.setAccessTokenValue(DUMMY_TOKEN);

        List<Authorization> list = new ArrayList<>();
        list.add(auth);
        when(authorizationRepository.findByPrincipalNameAndAccessTokenExpiresAt(eq("testClient"), any()))
                .thenReturn(list);

        RegisteredClient registeredClient = RegisteredClient.withId("testClient").clientId("testClient")
                .clientSecret("ChangeMe").authorizationGrantType(new AuthorizationGrantType("client_credentials"))
                .scope("RevokeToken").build();
        when(clientRegistrationManager.findById("testClient")).thenReturn(registeredClient);
        when(jwtTokenValidator.validateToken(DUMMY_TOKEN)).thenReturn(true);
        webTestClient.post().uri("/revoke/revokeByAdmin").headers(http -> {
            http.add("Authorization", "Bearer " + DUMMY_TOKEN);
            http.add("Content-Type", "application/x-www-form-urlencoded");
            http.add(IgniteOauth2CoreConstants.CORRELATION_ID, "abcd");
        }).bodyValue("clientId=testClient").exchange().expectStatus().isEqualTo(HttpStatus.OK);

    }

    /**
     * This test method tests the scenario where the revoke token request is successful but there is no active token. It
     * sets up the necessary parameters and then calls the revoke token method. The test asserts that the returned
     * status is HttpStatus.OK.
     */
    @Test
    void testRevokeTokenNoActiveToken() {
        Authorization auth = new Authorization();
        auth.setRegisteredClientId("testClient");
        auth.setPrincipalName("testClient");
        auth.setAuthorizationGrantType("client_credentials");
        auth.setAccessTokenMetadata(TOKEN_METADATA);

        auth.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        auth.setAccessTokenExpiresAt(Instant.now().plusSeconds(SECONDS_TO_ADD3));

        auth.setAccessTokenScopes("RevokeToken");
        auth.setAuthorizedScopes("RevokeToken");
        auth.setAccessTokenType(OAuth2TokenType.ACCESS_TOKEN.getValue());
        auth.setAccessTokenValue(DUMMY_TOKEN);

        when(authorizationRepository.findByAccessTokenValue("abcd")).thenReturn(Optional.of(auth));
        when(jwtTokenValidator.validateToken(DUMMY_TOKEN)).thenReturn(true);

        RegisteredClient registeredClient = RegisteredClient.withId("testClient").clientId("testClient")
                .clientSecret("ChangeMe").authorizationGrantType(new AuthorizationGrantType("client_credentials"))
                .scope("RevokeToken").build();
        when(clientRegistrationManager.findById("testClient")).thenReturn(registeredClient);
        webTestClient.post().uri("/revoke/revokeByAdmin").headers(http -> {
            http.add("Authorization", "Bearer " + DUMMY_TOKEN);
            http.add("Content-Type", "application/x-www-form-urlencoded");
            http.add(IgniteOauth2CoreConstants.CORRELATION_ID, "abcd");
        }).bodyValue("clientId=testClient").exchange().expectStatus().isEqualTo(HttpStatus.OK);

    }

    /**
     * This test method tests the scenario where the revoke token request throws an exception. It sets up the necessary
     * parameters and then calls the revoke token method. The test asserts that the returned status is
     * HttpStatus.INTERNAL_SERVER_ERROR.
     */
    @Test
    void testRevokeTokenException() {
        Authorization auth = new Authorization();
        auth.setRegisteredClientId("testClient");
        auth.setPrincipalName("testClient");
        auth.setAuthorizationGrantType("client_credentials");
        auth.setAccessTokenMetadata(TOKEN_METADATA);

        auth.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        auth.setAccessTokenExpiresAt(Instant.now().plusSeconds(SECONDS_TO_ADD3));

        auth.setAccessTokenScopes("RevokeToken");
        auth.setAuthorizedScopes("RevokeToken");
        auth.setAccessTokenType(OAuth2TokenType.ACCESS_TOKEN.getValue());
        auth.setAccessTokenValue(DUMMY_TOKEN);

        when(jwtTokenValidator.validateToken(DUMMY_TOKEN)).thenReturn(true);
        when(authorizationRepository.findByAccessTokenValue("abcd")).thenReturn(Optional.of(auth));
        List<Authorization> list = new ArrayList<>();
        list.add(auth);
        when(authorizationRepository.findByPrincipalNameAndAccessTokenExpiresAt(eq("testClient"), any()))
                .thenThrow(new RuntimeException());

        RegisteredClient registeredClient = RegisteredClient.withId("testClient").clientId("testClient")
                .clientSecret("ChangeMe").authorizationGrantType(new AuthorizationGrantType("client_credentials"))
                .scope("RevokeToken").build();
        when(clientRegistrationManager.findById("testClient")).thenReturn(registeredClient);
        webTestClient.post().uri("/revoke/revokeByAdmin").headers(http -> {
            http.add("Authorization", "Bearer " + DUMMY_TOKEN);
            http.add("Content-Type", "application/x-www-form-urlencoded");
            http.add(IgniteOauth2CoreConstants.CORRELATION_ID, "abcd");
        }).bodyValue("clientId=testClient").exchange().expectStatus().isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);

    }

    /**
     * This test method tests the scenario where the revoke token request is successful for a user. It sets up the
     * necessary parameters and then calls the revoke token method. The test asserts that the returned status is
     * HttpStatus.OK.
     */
    @Test
    void testRevokeTokenForUser() {
        Authorization auth = new Authorization();
        auth.setRegisteredClientId("testClient");
        auth.setPrincipalName("testClient");
        auth.setAuthorizationGrantType("client_credentials");
        auth.setAccessTokenMetadata(TOKEN_METADATA);

        auth.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        auth.setAccessTokenExpiresAt(Instant.now().plusSeconds(SECONDS_TO_ADD3));

        auth.setAccessTokenScopes("RevokeToken");
        auth.setAuthorizedScopes("RevokeToken");
        auth.setAccessTokenType(OAuth2TokenType.ACCESS_TOKEN.getValue());
        auth.setAccessTokenValue(DUMMY_TOKEN);

        when(jwtTokenValidator.validateToken(DUMMY_TOKEN)).thenReturn(true);
        when(authorizationRepository.findByAccessTokenValue("abcd")).thenReturn(Optional.of(auth));
        List<Authorization> list = new ArrayList<>();
        list.add(auth);
        when(authorizationRepository.findByPrincipalNameAndAccessTokenExpiresAt(eq("testClient"), any()))
                .thenReturn(list);

        RegisteredClient registeredClient = RegisteredClient.withId("testClient").clientId("testClient")
                .clientSecret("ChangeMe").authorizationGrantType(new AuthorizationGrantType("client_credentials"))
                .scope("RevokeToken").build();
        when(clientRegistrationManager.findById("testClient")).thenReturn(registeredClient);
        webTestClient.post().uri("/revoke/revokeByAdmin").headers(http -> {
            http.add("Authorization", "Bearer " + DUMMY_TOKEN);
            http.add("Content-Type", "application/x-www-form-urlencoded");
            http.add(IgniteOauth2CoreConstants.CORRELATION_ID, "abcd");
        }).bodyValue("username=testClient").exchange().expectStatus().isEqualTo(HttpStatus.OK);

    }

    /**
     * This test method tests the scenario where the revoke token request is unsuccessful due to no principal name. It
     * sets up the necessary parameters and then calls the revoke token method. The test asserts that the returned
     * status is HttpStatus.BAD_REQUEST.
     */
    @Test
    void testRevokeTokenNoPrincipalNameException() {
        Authorization auth = new Authorization();
        auth.setRegisteredClientId("testClient");
        auth.setPrincipalName("testClient");
        auth.setAuthorizationGrantType("client_credentials");
        auth.setAccessTokenMetadata(TOKEN_METADATA);

        auth.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        auth.setAccessTokenExpiresAt(Instant.now().plusSeconds(SECONDS_TO_ADD3));

        auth.setAccessTokenScopes("RevokeToken");
        auth.setAuthorizedScopes("RevokeToken");
        auth.setAccessTokenType(OAuth2TokenType.ACCESS_TOKEN.getValue());
        auth.setAccessTokenValue(DUMMY_TOKEN);

        when(jwtTokenValidator.validateToken(DUMMY_TOKEN)).thenReturn(true);
        when(authorizationRepository.findByAccessTokenValue("abcd")).thenReturn(Optional.of(auth));
        List<Authorization> list = new ArrayList<>();
        list.add(auth);
        when(authorizationRepository.findByPrincipalNameAndAccessTokenExpiresAt(eq("testClient"), any()))
                .thenReturn(list);

        RegisteredClient registeredClient = RegisteredClient.withId("testClient").clientId("testClient")
                .clientSecret("ChangeMe").authorizationGrantType(new AuthorizationGrantType("client_credentials"))
                .scope("RevokeToken").build();
        when(clientRegistrationManager.findById("testClient")).thenReturn(registeredClient);
        webTestClient.post().uri("/revoke/revokeByAdmin").headers(http -> {
            http.add("Authorization", "Bearer " + DUMMY_TOKEN);
            http.add("Content-Type", "application/x-www-form-urlencoded");
            http.add(IgniteOauth2CoreConstants.CORRELATION_ID, "abcd");
        })

                .exchange().expectStatus().isEqualTo(HttpStatus.BAD_REQUEST);

    }

    /**
     * This test method tests the scenario where the revoke token request is unauthorized. It sets up the necessary
     * parameters and then calls the revoke token method. The test asserts that the returned status is
     * HttpStatus.UNAUTHORIZED.
     */
    @Test
    void testRevokeToken_UnAuthorized() {
        webTestClient.post().uri("/revoke/revokeByAdmin").headers(http -> {
            http.add("Authorization", "Bearer abcd");
            http.add("Content-Type", "application/x-www-form-urlencoded");
            http.add(IgniteOauth2CoreConstants.CORRELATION_ID, "abcd");
        }).bodyValue("clientId=testClient").exchange().expectStatus().isEqualTo(HttpStatus.UNAUTHORIZED);

    }

    /**
     * This test method tests the scenario where the revoke token request is successful but the correlation id is
     * missing. It sets up the necessary parameters and then calls the revoke token method. The test asserts that the
     * returned status is HttpStatus.OK.
     */
    @Test
    void testRevokeTokenCorrelationIdMissing() {
        Authorization auth = new Authorization();
        auth.setRegisteredClientId("testClient");
        auth.setPrincipalName("testClient");
        auth.setAuthorizationGrantType("client_credentials");
        auth.setAccessTokenMetadata(TOKEN_METADATA);

        auth.setAttributes("{\"@class\":\"java.util.Collections$UnmodifiableMap\"}");
        auth.setAccessTokenExpiresAt(Instant.now().plusSeconds(SECONDS_TO_ADD3));

        auth.setAccessTokenScopes("RevokeToken");
        auth.setAuthorizedScopes("RevokeToken");
        auth.setAccessTokenType(OAuth2TokenType.ACCESS_TOKEN.getValue());
        auth.setAccessTokenValue(DUMMY_TOKEN);
        when(jwtTokenValidator.validateToken(DUMMY_TOKEN)).thenReturn(true);
        when(authorizationRepository.findByAccessTokenValue("abcd")).thenReturn(Optional.of(auth));
        List<Authorization> list = new ArrayList<>();
        list.add(auth);
        when(authorizationRepository.findByPrincipalNameAndAccessTokenExpiresAt(eq("testClient"), any()))
                .thenReturn(list);

        RegisteredClient registeredClient = RegisteredClient.withId("testClient").clientId("testClient")
                .clientSecret("ChangeMe").authorizationGrantType(new AuthorizationGrantType("client_credentials"))
                .scope("RevokeToken").build();
        when(clientRegistrationManager.findById("testClient")).thenReturn(registeredClient);
        webTestClient.post().uri("/revoke/revokeByAdmin").headers(http -> {
            http.add("Authorization", "Bearer " + DUMMY_TOKEN);
            http.add("Content-Type", "application/x-www-form-urlencoded");
        }).bodyValue("clientId=testClient").exchange().expectStatus().isEqualTo(HttpStatus.OK);

    }

    /**
     * This test method tests the scenario where the revoke token request is successful but the client id is missing. It
     * sets up the necessary parameters and then calls the revoke token method. The test asserts that the returned
     * status is HttpStatus.OK.
     */
    @TestConfiguration
    static class TestConfig {

        @Bean 
        @Primary
        public TenantConfigurationService tenantConfigurationService() {
            

            // Create a mock TenantProperties with required keystore properties
            TenantProperties mockTenantProperties = new TenantProperties();
            // Set external IDP and internal login flags to prevent NPE in security config
            mockTenantProperties.setExternalIdpEnabled(false);
            mockTenantProperties.setInternalLoginEnabled(true);

            // Set up keystore properties required by KeyStoreConfigByJavaKeyStore
            HashMap<String, String> keystoreProperties = new HashMap<>();
            keystoreProperties.put(TENANT_KEYSTORE_TYPE, "JKS");
            keystoreProperties.put(TENANT_KEYSTORE_FILENAME, "uidamauthserver.jks");
            keystoreProperties.put(TENANT_KEYSTORE_PASS, "uidam-test-pwd");
            keystoreProperties.put(TENANT_KEYSTORE_ALIAS, "uidam-dev");
            mockTenantProperties.setKeyStore(keystoreProperties);
            TenantConfigurationService mockService = Mockito.mock(TenantConfigurationService.class);
            // Mock the TenantConfigurationService to return our mock TenantProperties
            when(mockService.getTenantProperties(ECSP)).thenReturn(mockTenantProperties);

            return mockService;
        }
    }
}
