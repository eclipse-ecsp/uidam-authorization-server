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

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.SneakyThrows;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.AccountProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MultiTenantProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.entities.AuthorizationSecurityContext;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationSecurityContextRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.context.HttpRequestResponseHolder;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ATTRIBUTE_SUB;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.EXTERNAL_IDP_PRINCIPAL;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.GRANTED_AUTORITIES;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.REGISTRATION_ID_GOOGLE;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.REQUESTED_SESSION_ID;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.SECONDS_300;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_USER_NAME;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the DatabaseSecurityContextRepository.
 */
class DatabaseSecurityContextRepositoryTest {

    DatabaseSecurityContextRepository databaseSecurityContextRepository;
    @Mock
    AuthorizationSecurityContextRepository authorizationSecurityContextRepository;
    @Mock
    private TenantConfigurationService tenantConfigurationService;
    @Mock
    private TenantProperties tenantProperties;
    @Mock
    SecurityContextHolderStrategy securityContextHolderStrategy;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    /**
     * This method sets up the test environment before each test.
     * It initializes the mocks and sets the tenant properties.
     */
    @BeforeEach
    void setUp() {
        this.authorizationSecurityContextRepository = mock(AuthorizationSecurityContextRepository.class);
        this.securityContextHolderStrategy = mock(SecurityContextHolderStrategy.class);
        this.tenantProperties = mock(TenantProperties.class);
        MultiTenantProperties multiTenantProperties = mock(MultiTenantProperties.class);
        when(multiTenantProperties.getTenantProperties(anyString())).thenReturn(tenantProperties);
        tenantConfigurationService = new TenantConfigurationService(multiTenantProperties);
        request = new MockHttpServletRequest();
        request.setRequestedSessionId(REQUESTED_SESSION_ID);
        // Create a MockHttpSession
        MockHttpSession session = new MockHttpSession() {
            @Override
            public String getId() {
                return REQUESTED_SESSION_ID; // Return your desired session ID
            }
        };

        // Attach the session to the request
        request.setSession(session);

        // Attach the session to the request
        request.setSession(session);
        response = new MockHttpServletResponse();
        databaseSecurityContextRepository = new DatabaseSecurityContextRepository(
            authorizationSecurityContextRepository, tenantConfigurationService, "5m");
        
        // Mock the account properties
        AccountProperties accountProperties = Mockito.mock(AccountProperties.class);
        when(accountProperties.getAccountName()).thenReturn(ACCOUNT_NAME);
        when(tenantProperties.getAccount()).thenReturn(accountProperties);
        
        // Mock multiTenantProperties.getTenants() to return a map with the ecsp tenant
        Map<String, TenantProperties> tenantsMap = new HashMap<>();
        tenantsMap.put("ecsp", tenantProperties);
        when(multiTenantProperties.getTenants()).thenReturn(tenantsMap);
    }

    /**
     * This test method tests the loadContext method of the DatabaseSecurityContextRepository.
     * It asserts that the returned context is an empty SecurityContext.
     */
    @Test
    void loadContext() {
        SecurityContext context = databaseSecurityContextRepository.loadContext(new HttpRequestResponseHolder(request,
            response));
        assertEquals(SecurityContextHolder.createEmptyContext(), context);
    }

    /**
     * This test method tests the loadDeferredContext method of the DatabaseSecurityContextRepository.
     * It asserts that the returned context is not null.
     */
    @Test
    void loadDeferredContext() {
        when(securityContextHolderStrategy.createEmptyContext()).thenReturn(new SecurityContextImpl());
        databaseSecurityContextRepository.setSecurityContextHolderStrategy(securityContextHolderStrategy);
        Supplier<SecurityContext> deferredContext = databaseSecurityContextRepository.loadDeferredContext(request);
        assertNotNull(deferredContext.get());
        verify(securityContextHolderStrategy, times(1)).createEmptyContext();
    }

    /**
     * This test method tests the saveContext method when the context is authenticated.
     * It asserts that no exception is thrown and the save method of the AuthorizationSecurityContextRepository is
     * called once.
     */
    @Test
    void saveContextAuthenticatedSuccess() {
        SecurityContext securityContext = new SecurityContextImpl();
        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
            TEST_PASSWORD, null, null);
        securityContext.setAuthentication(authentication);
        assertDoesNotThrow(() ->
                databaseSecurityContextRepository.saveContext(securityContext, request, response));
        verify(authorizationSecurityContextRepository, times(1)).save(any());
    }

    /**
     * This test method tests the saveContext method when the context is authenticated with an external IDP.
     * It asserts that no exception is thrown and the save method of the AuthorizationSecurityContextRepository is
     * called once.
     */
    @Test
    void saveContextAuthenticatedSuccessExternalIdp() {
        SecurityContext securityContext = new SecurityContextImpl();
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(oauth2User, null,
            REGISTRATION_ID_GOOGLE);
        securityContext.setAuthentication(authentication);
        assertDoesNotThrow(() ->
            databaseSecurityContextRepository.saveContext(securityContext, request, response));
        verify(authorizationSecurityContextRepository, times(1)).save(any());
    }

    /**
     * This test method tests the saveContext method when the context is authenticated but the session is not.
     * It asserts that no exception is thrown and the save method of the AuthorizationSecurityContextRepository is
     * called once.
     */
    @Test
    void saveContextAuthenticatedSuccessForUnauthenticated() {
        findBySessionIdMock(false);
        SecurityContext securityContext = new SecurityContextImpl();
        CustomUserPwdAuthenticationToken authentication = new CustomUserPwdAuthenticationToken(TEST_USER_NAME,
            TEST_PASSWORD, null, null);
        securityContext.setAuthentication(authentication);
        assertDoesNotThrow(() ->
            databaseSecurityContextRepository.saveContext(securityContext, request, response));
        verify(authorizationSecurityContextRepository, times(1)).save(any());
    }

    /**
     * This test method tests the saveContext method when the context is unauthenticated.
     * It sets up the necessary parameters and then calls the saveContext method.
     * The test asserts that no exception is thrown and the save method of the AuthorizationSecurityContextRepository is
     * called once.
     */
    @Test
    void saveContextUnauthenticatedSuccess() {
        findBySessionIdMock(false);
        SecurityContext securityContext = new SecurityContextImpl();
        assertDoesNotThrow(() ->
                databaseSecurityContextRepository.saveContext(securityContext, request, response));
        verify(authorizationSecurityContextRepository, times(1)).save(any());
    }

    /**
     * This test method tests the saveContext method when the context is null.
     * It asserts that no exception is thrown and the save method of the AuthorizationSecurityContextRepository is not
     * called.
     */
    @Test
    void saveContextNull() {
        assertDoesNotThrow(() ->
            databaseSecurityContextRepository.saveContext(null, request, response));
        verify(authorizationSecurityContextRepository, times(0)).save(any());
    }

    /**
     * This test method tests the saveContext method when the session ID is null.
     * It asserts that no exception is thrown and the save method of the AuthorizationSecurityContextRepository is not
     * called.
     */
    @Test
    void saveContextUnauthenticatedNullSessionId() {
        request.setRequestedSessionId(null);
        SecurityContext securityContext = new SecurityContextImpl();
        assertDoesNotThrow(() ->
                databaseSecurityContextRepository.saveContext(securityContext, request, response));
        verify(authorizationSecurityContextRepository, times(0)).save(any());
    }

    /**
     * This test method tests the saveContext method when the findBySessionId method returns null.
     * It asserts that no exception is thrown and the save method of the AuthorizationSecurityContextRepository is not
     * called.
     */
    @Test
    void saveContextUnauthenticatedNullFindBySessionId() {
        when(authorizationSecurityContextRepository.findBySessionId(REQUESTED_SESSION_ID)).thenReturn(Optional.empty());
        SecurityContext securityContext = new SecurityContextImpl();
        assertDoesNotThrow(() ->
                databaseSecurityContextRepository.saveContext(securityContext, request, response));
        verify(authorizationSecurityContextRepository, times(0)).save(any());
    }

    /**
     * This test method tests the containsContext method when the context is found.
     * It asserts that the returned value is true.
     */
    @Test
    void containsContextSuccess() {
        findBySessionIdMock(true);
        assertTrue(databaseSecurityContextRepository.containsContext(request));
    }

    /**
     * This test method tests the containsContext method when the context is found with an external IDP.
     * It asserts that the returned value is true.
     */
    @SneakyThrows
    @Test
    void containsContextSuccessExternalIdp() {
        findBySessionIdMockExternalIdp();
        assertTrue(databaseSecurityContextRepository.containsContext(request));
    }

    /**
     * This test method tests the containsContext method when the context is null.
     * It asserts that the returned value is false.
     */
    @Test
    void containsContextNullContext() {
        assertFalse(databaseSecurityContextRepository.containsContext(request));
    }

    /**
     * This test method tests the containsContext method when the authentication context is null.
     * It asserts that the returned value is false.
     */
    @Test
    void containsContextNullAuthenticationContext() {
        assertFalse(databaseSecurityContextRepository.containsContext(request));
    }

    /**
     * This test method tests the containsContext method when the session ID is null.
     * It asserts that the returned value is false.
     */
    @Test
    void containsContextNullSessionId() {
        request.setRequestedSessionId(null);
        assertFalse(databaseSecurityContextRepository.containsContext(request));
    }

    /**
     * This test method tests the containsContext method when the findBySessionId method returns null.
     * It sets up the necessary parameters and then calls the containsContext method.
     * The test asserts that the returned value is false.
     */
    @Test
    void containsContextNullFindBySessionId() {
        when(authorizationSecurityContextRepository.findBySessionId(REQUESTED_SESSION_ID)).thenReturn(Optional.empty());
        assertFalse(databaseSecurityContextRepository.containsContext(request));
    }

    /**
     * This test method tests the containsContext method when the context is not authenticated.
     * It sets up the necessary parameters and then calls the containsContext method.
     * The test asserts that the returned value is false.
     */
    @Test
    void containsContextAuthenticatedFalse() {
        findBySessionIdMock(false);
        assertFalse(databaseSecurityContextRepository.containsContext(request));
    }

    /**
     * This helper method sets up the necessary parameters for the findBySessionId method.
     * It creates an AuthorizationSecurityContext and sets its properties based on the provided parameters.
     * The method then mocks the findBySessionId method of the AuthorizationSecurityContextRepository to return the
     * created AuthorizationSecurityContext.
     */
    void findBySessionIdMock(boolean authenticated) {
        AuthorizationSecurityContext authorizationSecurityContext = new AuthorizationSecurityContext();
        authorizationSecurityContext.setPrincipal(TEST_USER_NAME);
        authorizationSecurityContext.setAuthorities(GRANTED_AUTORITIES);
        authorizationSecurityContext.setAuthenticated(authenticated);
        authorizationSecurityContext.setSessionId(REQUESTED_SESSION_ID);
        Timestamp currentTimestamp = Timestamp.from(Instant.now());
        authorizationSecurityContext.setCreatedDate(currentTimestamp);
        authorizationSecurityContext.setUpdatedDate(currentTimestamp);
        when(authorizationSecurityContextRepository.findBySessionId(REQUESTED_SESSION_ID)).thenReturn(
            Optional.of(authorizationSecurityContext));
    }

    /**
     * This helper method sets up the necessary parameters for the findBySessionId method for an external IDP.
     * It creates an AuthorizationSecurityContext and sets its properties based on the provided parameters.
     * The method then mocks the findBySessionId method of the AuthorizationSecurityContextRepository to return the
     * created AuthorizationSecurityContext.
     */
    void findBySessionIdMockExternalIdp() throws JsonProcessingException {
        AuthorizationSecurityContext authorizationSecurityContext = new AuthorizationSecurityContext();
        authorizationSecurityContext.setPrincipal(EXTERNAL_IDP_PRINCIPAL);
        authorizationSecurityContext.setAuthorities(GRANTED_AUTORITIES);
        authorizationSecurityContext.setAuthorizedClientRegistrationId(REGISTRATION_ID_GOOGLE);
        authorizationSecurityContext.setAuthenticated(true);
        authorizationSecurityContext.setSessionId(REQUESTED_SESSION_ID);
        Timestamp currentTimestamp = Timestamp.from(Instant.now());
        authorizationSecurityContext.setCreatedDate(currentTimestamp);
        authorizationSecurityContext.setUpdatedDate(currentTimestamp);
        when(authorizationSecurityContextRepository.findBySessionId(REQUESTED_SESSION_ID)).thenReturn(
            Optional.of(authorizationSecurityContext));
    }

    /**
     * This test method tests the containsContext method when the session has timed out.
     * It sets up the necessary parameters and then calls the containsContext method.
     * The test asserts that the returned value is false.
     */
    @Test
    void containsContextSessionTimeout() {
        AuthorizationSecurityContext authorizationSecurityContext = new AuthorizationSecurityContext();
        authorizationSecurityContext.setPrincipal(TEST_USER_NAME);
        authorizationSecurityContext.setAuthenticated(true);
        authorizationSecurityContext.setSessionId(REQUESTED_SESSION_ID);
        authorizationSecurityContext.setAuthorities(GRANTED_AUTORITIES);
        Timestamp currentTimestamp = Timestamp.from(Instant.now().minusSeconds(SECONDS_300));
        authorizationSecurityContext.setCreatedDate(currentTimestamp);
        authorizationSecurityContext.setUpdatedDate(currentTimestamp);
        when(authorizationSecurityContextRepository.findBySessionId(REQUESTED_SESSION_ID)).thenReturn(
            Optional.of(authorizationSecurityContext));
        assertFalse(databaseSecurityContextRepository.containsContext(request));
    }

}