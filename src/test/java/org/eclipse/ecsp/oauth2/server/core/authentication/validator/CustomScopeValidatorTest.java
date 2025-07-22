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

package org.eclipse.ecsp.oauth2.server.core.authentication.validator;

import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ClientProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ATTRIBUTE_SUB;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.REGISTRATION_ID_GOOGLE;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_CLIENT_ID;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_USER_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.URI;
import static org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients.registeredClient;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the CustomScopeValidator.
 */
class CustomScopeValidatorTest {

    private static final int INT_300 = 300;

    private static final int INT_7200 = 7200;

    private static final int INT_3600 = 3600;

    @InjectMocks
    private CustomScopeValidator customScopeValidator;

    @Mock
    private CacheClientUtils cacheClientUtils;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    private AutoCloseable closeable;

    @BeforeEach
    void setUp() {
        closeable = MockitoAnnotations.openMocks(this);

        // Set up tenant context for tests
        TenantContext.setCurrentTenant("ecsp");

        // Mock tenant configuration service to return test properties with proper nested objects
        TenantProperties mockTenantProperties = createMockTenantProperties(true); 
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mockTenantProperties);
    }

    private TenantProperties createMockTenantProperties(boolean enableScopeCustomization) {
        TenantProperties tenantProperties = new TenantProperties();
        tenantProperties.setTenantId("ecsp");
        tenantProperties.setTenantName("ECSP Test Tenant");

        // Initialize client properties
        ClientProperties clientProperties = new ClientProperties();
        clientProperties.setOauthScopeCustomization(enableScopeCustomization);
        clientProperties.setAccessTokenTtl(INT_3600);
        clientProperties.setIdTokenTtl(INT_3600);
        clientProperties.setRefreshTokenTtl(INT_7200);
        clientProperties.setAuthCodeTtl(INT_300);
        tenantProperties.setClient(clientProperties);

        return tenantProperties;
    }

    @AfterEach
    void tearDown() throws Exception {
        // Clear tenant context after each test
        TenantContext.clear();

        // Close mockito annotations
        if (closeable != null) {
            closeable.close();
        }
    }

    /**
     * This method tests the scenario where the scope validation is successful. It sets up the necessary parameters and
     * then calls the accept method. The test asserts that no exception is thrown.
     */
    @Test
    void acceptSuccess() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("SelfManage"));
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, authorities);
        Set<String> scopes = new HashSet<>();
        scopes.add("SelfManage");
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = 
                new OAuth2AuthorizationCodeRequestAuthenticationToken(URI, TEST_CLIENT_ID, principal, URI, null, scopes,
                        null);
        RegisteredClient registeredClient = registeredClient().build();
        OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext = 
                OAuth2AuthorizationCodeRequestAuthenticationContext.with(authorizationCodeRequestAuthentication)
                        .registeredClient(registeredClient).build();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        assertDoesNotThrow(() -> customScopeValidator.accept(authenticationContext));
    }

    /**
     * This method tests the scenario where the scope validation is successful for an external identity provider. It
     * sets up the necessary parameters and then calls the accept method. The test asserts that no exception is thrown.
     */
    @Test
    void acceptForExternalIdp() {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken principal = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);
        Set<String> scopes = new HashSet<>();
        scopes.add("SelfManage");
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = 
                new OAuth2AuthorizationCodeRequestAuthenticationToken(URI, TEST_CLIENT_ID, principal, URI, null, scopes,
                        null);
        RegisteredClient registeredClient = registeredClient().build();
        OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext = 
                OAuth2AuthorizationCodeRequestAuthenticationContext.with(authorizationCodeRequestAuthentication)
                        .registeredClient(registeredClient).build();

        assertDoesNotThrow(() -> customScopeValidator.accept(authenticationContext));
    }

    /**
     * This method tests the scenario where the scope validation fails due to client scopes. It sets up the necessary
     * parameters and then calls the accept method. The test expects an
     * OAuth2AuthorizationCodeRequestAuthenticationException to be thrown.
     */
    @Test
    void acceptFailClientScopes() {
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        Set<String> scopes = new HashSet<>();
        scopes.add("scope2");
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = 
                new OAuth2AuthorizationCodeRequestAuthenticationToken(URI, TEST_CLIENT_ID, principal, URI, null, scopes,
                        null);
        RegisteredClient registeredClient = registeredClient().build();
        OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext = 
                OAuth2AuthorizationCodeRequestAuthenticationContext.with(authorizationCodeRequestAuthentication)
                        .registeredClient(registeredClient).build();

        assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> customScopeValidator.accept(authenticationContext));
    }

    /**
     * This method tests the scenario where the scope validation fails due to user scopes. It sets up the necessary
     * parameters and then calls the accept method. The test expects an
     * OAuth2AuthorizationCodeRequestAuthenticationException to be thrown.
     */
    @Test
    void acceptFailUserScopes() {
        // For this test, we need scope validation enabled (oauthScopeCustomization = false)
        TenantProperties testTenantProperties = createMockTenantProperties(false);
        when(tenantConfigurationService.getTenantProperties()).thenReturn(testTenantProperties);

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("scope2"));
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, authorities);
        Set<String> scopes = new HashSet<>();
        scopes.add("SelfManage");
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = 
                new OAuth2AuthorizationCodeRequestAuthenticationToken(URI, TEST_CLIENT_ID, principal, URI, null, scopes,
                        null);
        RegisteredClient registeredClient = registeredClient().build();
        OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext = 
                OAuth2AuthorizationCodeRequestAuthenticationContext.with(authorizationCodeRequestAuthentication)
                        .registeredClient(registeredClient).build();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> customScopeValidator.accept(authenticationContext));
    }

}