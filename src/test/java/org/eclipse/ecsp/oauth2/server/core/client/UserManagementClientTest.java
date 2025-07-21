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

package org.eclipse.ecsp.oauth2.server.core.client;

import io.prometheus.client.CollectorRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.http.HttpStatus;
import org.eclipse.ecsp.oauth2.server.core.common.UpdatePasswordData;
import org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants;
import org.eclipse.ecsp.oauth2.server.core.config.TenantContext;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.AccountProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UserProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.UserNotFoundException;
import org.eclipse.ecsp.oauth2.server.core.request.dto.FederatedUserDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserEvent;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.response.UserErrorResponse;
import org.eclipse.ecsp.oauth2.server.core.response.dto.PasswordPolicyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.service.impl.CaptchaServiceImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Optional;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_ADD_USER_EVENTS_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_CREATE_FEDRATED_USER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_PASSWORD_POLICY_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_SELF_CREATE_USER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_BY_USERNAME_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_MANAGEMENT_ENV;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_RECOVERY_NOTIF_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_RESET_PASSWORD_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.USER_BY_USERNAME_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.USER_EVENT_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.USER_MGMT_BASE_URL;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.USER_RECOVERY_NOTIF_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.USER_RESET_PASSWORD_ENDPOINT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the UserManagementClient.
 */
@SuppressWarnings({ "unchecked", "rawtypes" })
class UserManagementClientTest {
    public static final int MIN_LENGTH = 8;
    public static final int MAX_LENGTH = 16;

    private UserManagementClient userManagementClient;

    @Mock
    private WebClient webClientMock;

    @Mock
    private WebClient.RequestBodyUriSpec requestBodyUriSpecMock;

    @Mock
    private WebClient.RequestBodySpec requestBodySpecMock;

    @Mock
    private WebClient.ResponseSpec responseSpecMock;

    @Mock
    private Mono<ResponseEntity<Void>> responseMock;

    @Mock
    private WebClient.RequestHeadersSpec requestHeadersSpecMock;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private CaptchaServiceImpl captchaService;

    @Mock
    private HttpServletRequest httpServletRequest;

    private AutoCloseable closeable;

    /**
     * This method sets up the test environment before each test. It sets up the tenant context and mocks.
     */
    @BeforeEach
    void setup() {
        closeable = MockitoAnnotations.openMocks(this);
        // Set up tenant context for testing
        TenantContext.setCurrentTenant("ecsp");

        // Set up global mock for tenant configuration service
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mockTenantProperties);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        // Create UserManagementClient with mocked WebClient for testing
        userManagementClient = new UserManagementClient(tenantConfigurationService, captchaService, webClientMock);
    }

    private TenantProperties createMockTenantProperties() {
        TenantProperties tenantProperties = new TenantProperties();
        tenantProperties.setTenantId("ecsp");
        tenantProperties.setTenantName("ECSP Test Tenant");

        // Set up mock external URLs
        HashMap<String, String> externalUrls = new HashMap<>();
        externalUrls.put(TENANT_EXTERNAL_URLS_USER_MANAGEMENT_ENV, USER_MGMT_BASE_URL);
        externalUrls.put(TENANT_EXTERNAL_URLS_USER_BY_USERNAME_ENDPOINT, USER_BY_USERNAME_ENDPOINT);
        externalUrls.put(TENANT_EXTERNAL_URLS_ADD_USER_EVENTS_ENDPOINT, USER_EVENT_ENDPOINT);
        externalUrls.put(TENANT_EXTERNAL_URLS_USER_RECOVERY_NOTIF_ENDPOINT, USER_RECOVERY_NOTIF_ENDPOINT);
        externalUrls.put(TENANT_EXTERNAL_URLS_USER_RESET_PASSWORD_ENDPOINT, USER_RESET_PASSWORD_ENDPOINT);
        externalUrls.put(TENANT_EXTERNAL_URLS_PASSWORD_POLICY_ENDPOINT, "/v1/users/password-policy");
        externalUrls.put(TENANT_EXTERNAL_URLS_SELF_CREATE_USER, "/v1/users/self-create");
        externalUrls.put(TENANT_EXTERNAL_URLS_CREATE_FEDRATED_USER, "/v1/users/federated");
        tenantProperties.setExternalUrls(externalUrls);

        // Set up mock account properties
        AccountProperties accountProperties = new AccountProperties();
        accountProperties.setAccountName(ACCOUNT_NAME);
        tenantProperties.setAccount(accountProperties);

        // Set up mock user properties
        UserProperties userProperties = new UserProperties();
        userProperties.setDefaultRole("USER");
        tenantProperties.setUser(userProperties);

        return tenantProperties;
    }

    /**
     * This method cleans up the test environment after each test. It clears the tenant context and the default registry
     * of the CollectorRegistry.
     */
    @AfterEach
    void cleanup() throws Exception {
        TenantContext.clear();
        CollectorRegistry.defaultRegistry.clear();

        if (closeable != null) {
            closeable.close();
        }
    }

    /**
     * This method tests the scenario where the getUserDetailsByUsername method is successful. It sets up the necessary
     * parameters and then calls the getUserDetailsByUsername method. The test asserts that the returned
     * UserDetailsResponse is not null.
     */
    @Test
    void testGetUserDetailsByUsernameSuccess() {
        // Create a properly populated UserDetailsResponse
        UserDetailsResponse expectedResponse = new UserDetailsResponse();
        expectedResponse.setUserName("testUser");
        expectedResponse.setEmail("testUser@example.com");
        expectedResponse.setVerificationEmailSent(false);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(any(), Optional.ofNullable(any()))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.accept(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(UserDetailsResponse.class)).thenReturn(Mono.just(expectedResponse));
        UserDetailsResponse userDetailsResponse = userManagementClient.getUserDetailsByUsername("testUser",
                "testAccount");
        assertNotNull(userDetailsResponse);
        assertEquals("testUser", userDetailsResponse.getUserName());
        assertEquals("testUser@example.com", userDetailsResponse.getEmail());
    }

    /**
     * This method tests the scenario where the getUserDetailsByUsername method is called with a null account. It sets
     * up the necessary parameters and then calls the getUserDetailsByUsername method. The test asserts that the
     * returned UserDetailsResponse is not null.
     */
    @Test
    void testGetUserDetailsByUsernameAccountFromConfig() {
        // Create a properly populated UserDetailsResponse
        UserDetailsResponse expectedResponse = new UserDetailsResponse();
        expectedResponse.setUserName("testUser");
        expectedResponse.setEmail("testUser@example.com");
        expectedResponse.setVerificationEmailSent(false);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(any(), Optional.ofNullable(any()))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.accept(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(UserDetailsResponse.class)).thenReturn(Mono.just(expectedResponse));
        UserDetailsResponse userDetailsResponse = userManagementClient.getUserDetailsByUsername("testUser", null);
        assertNotNull(userDetailsResponse);
        assertEquals("testUser", userDetailsResponse.getUserName());
        assertEquals("testUser@example.com", userDetailsResponse.getEmail());
    }

    /**
     * This method tests the scenario where the getUserDetailsByUsername method throws an exception. It sets up the
     * necessary parameters and then calls the getUserDetailsByUsername method. The test asserts that an
     * OAuth2AuthenticationException is thrown.
     */
    @Test
    void testGetUserDetailsByUsernameException() {
        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(any(), Optional.ofNullable(any()))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.accept(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(UserDetailsResponse.class)).thenReturn(Mono.error(new RuntimeException()));
        Exception thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername("testUser", "testAccount"));
        assertEquals("Unable to validate " + OAuth2ParameterNames.USERNAME, thrown.getMessage());
    }

    /**
     * This method tests the scenario where the addUserEvent method is successful. It sets up the necessary parameters
     * and then calls the addUserEvent method. The test asserts that the returned string is not null.
     */
    @Test
    void testAddUserEventSuccess() {
        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(any(), Optional.ofNullable(any()))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.bodyValue(any())).thenReturn(requestHeadersSpecMock);

        when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(String.class)).thenReturn(Mono.just(new String("")));

        UserEvent userEvent = new UserEvent();
        userEvent.setType("Login_Attempt");
        userEvent.setResult("Success");
        userEvent.setMessage("login sucessfully!");
        String response = userManagementClient.addUserEvent(userEvent, "6f452624-c4e3-40ff-ba29-fe9082705f50");
        assertNotNull(response);
    }

    /**
     * This method tests the scenario where the addUserEvent method throws an exception. It sets up the necessary
     * parameters and then calls the addUserEvent method. The test asserts that an OAuth2AuthenticationException is
     * thrown.
     */
    @Test
    void testAddUserEventException() {
        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(any(), Optional.ofNullable(any()))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.bodyValue(any())).thenReturn(requestHeadersSpecMock);

        when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(String.class)).thenReturn(Mono.error(new RuntimeException()));

        UserEvent userEvent = new UserEvent();
        userEvent.setType("Login_Attempt");
        userEvent.setResult("Success");
        userEvent.setMessage("login sucessfully!");
        Exception thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.addUserEvent(userEvent, "6f452624-c4e3-40ff-ba29-fe9082705f50"));
        assertEquals("failed to process user event", thrown.getMessage());
    }

    /**
     * This method tests the scenario where the updateUserPasswordUsingRecoverySecret method is successful. It sets up
     * the necessary parameters and then calls the updateUserPasswordUsingRecoverySecret method. The test asserts that
     * the returned string is not null.
     */
    @Test
    void testUpdatePassword() {
        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(ArgumentMatchers.<String>notNull())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.bodyValue(any())).thenReturn(requestHeadersSpecMock);

        when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(String.class)).thenReturn(Mono.just(new String("")));
        String response = userManagementClient.updateUserPasswordUsingRecoverySecret(
                UpdatePasswordData.of("6f452624-c4e3-40ff-ba29-fe9082705f50", "password"));
        assertNotNull(response);

    }

    /**
     * This method tests the scenario where the updateUserPasswordUsingRecoverySecret method throws a bad request
     * exception. It sets up the necessary parameters and then calls the updateUserPasswordUsingRecoverySecret method.
     * The test asserts that a RuntimeException is thrown.
     */
    @Test
    void testUpdatePasswordExceptionBadRequest() {
        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(ArgumentMatchers.<String>notNull())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.bodyValue(any())).thenReturn(requestHeadersSpecMock);

        when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(String.class)).thenReturn(
                Mono.error(new WebClientResponseException(HttpStatus.SC_BAD_REQUEST, ACCOUNT_NAME, null, null, null)));
        Exception thrown = assertThrows(RuntimeException.class,
                () -> userManagementClient.updateUserPasswordUsingRecoverySecret(
                        UpdatePasswordData.of("6f452624-c4e3-40ff-ba29-fe9082705f50", "password")));

        assertNotNull(thrown.getMessage());
    }

    /**
     * This method tests the scenario where the updateUserPasswordUsingRecoverySecret method throws an internal server
     * error exception. It sets up the necessary parameters and then calls the updateUserPasswordUsingRecoverySecret
     * method. The test asserts that a RuntimeException is thrown.
     */
    @Test
    void testUpdatePasswordException() {
        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(ArgumentMatchers.<String>notNull())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.bodyValue(any())).thenReturn(requestHeadersSpecMock);

        when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(String.class)).thenReturn(Mono.error(
                new WebClientResponseException(HttpStatus.SC_INTERNAL_SERVER_ERROR, ACCOUNT_NAME, null, null, null)));
        Exception thrown = assertThrows(RuntimeException.class,
                () -> userManagementClient.updateUserPasswordUsingRecoverySecret(
                        UpdatePasswordData.of("6f452624-c4e3-40ff-ba29-fe9082705f50", "password")));

        Assert.hasText(thrown.getMessage(), "failed to process request");
    }

    /**
     * This method tests the scenario where the sendUserResetPasswordNotification method is successful. It sets up the
     * necessary parameters and then calls the sendUserResetPasswordNotification method. The test asserts that the
     * returned string is not null.
     */
    @Test
    void testPasswordRecoveryNotif() {
        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(any(), Optional.ofNullable(any()))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.toBodilessEntity()).thenReturn(Mono.just(ResponseEntity.ok().build()));
        userManagementClient.sendUserResetPasswordNotification("6f452624-c4e3-40ff-ba29-fe9082705f50", "ignite");
        verify(webClientMock, times(1)).method(HttpMethod.POST);
    }

    /**
     * This method tests the scenario where the sendUserResetPasswordNotification method throws a bad request exception.
     * It sets up the necessary parameters and then calls the sendUserResetPasswordNotification method. The test asserts
     * that a RuntimeException is thrown.
     */
    @Test
    void testPasswordResetNotificationException() {
        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(any(), Optional.ofNullable(any()))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.bodyValue(any())).thenReturn(requestHeadersSpecMock);

        when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(String.class)).thenReturn(
                Mono.error(new WebClientResponseException(HttpStatus.SC_BAD_REQUEST, ACCOUNT_NAME, null, null, null)));

        Exception thrown = assertThrows(RuntimeException.class, () -> userManagementClient
                .sendUserResetPasswordNotification("6f452624-c4e3-40ff-ba29-fe9082705f50", "ignite"));
        assertNotNull(thrown.getMessage());
    }

    /**
     * This method tests the scenario where the sendUserResetPasswordNotification method throws a not found exception.
     * It sets up the necessary parameters and then calls the sendUserResetPasswordNotification method. The test asserts
     * that a UserNotFoundException is thrown.
     */
    @Test
    void testPasswordResetNotificationExceptionNotFound() {
        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(any(), Optional.ofNullable(any()))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.toBodilessEntity()).thenReturn(
                Mono.error(new WebClientResponseException(HttpStatus.SC_NOT_FOUND, ACCOUNT_NAME, null, null, null)));

        Exception thrown = assertThrows(UserNotFoundException.class, () -> userManagementClient
                .sendUserResetPasswordNotification("6f452624-c4e3-40ff-ba29-fe9082705f50", "ignite"));
        assertNotNull(thrown.getMessage());
    }

    private UserDetailsResponse getUserDetailsResponse() {
        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setEmail("test@example.com");
        userDetailsResponse.setVerificationEmailSent(true);
        // Set other necessary fields...
        return userDetailsResponse;
    }

    @Test
    void passwordPolicyFetchedSuccessfully() {
        PasswordPolicyResponseDto expectedResponse = new PasswordPolicyResponseDto();
        expectedResponse.setMinLength(MIN_LENGTH);
        expectedResponse.setMaxLength(MAX_LENGTH);
        getUserDetailsResponse();

        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(PasswordPolicyResponseDto.class))
                .thenReturn(Mono.just(expectedResponse));

        PasswordPolicyResponseDto response = userManagementClient.getPasswordPolicy();
        assertNotNull(response);
        assertEquals(expectedResponse.getMinLength(), response.getMinLength());
        assertEquals(expectedResponse.getMaxLength(), response.getMaxLength());
    }

    @Test
    void passwordPolicyReturnsNullWhenOauth2AuthenticationExceptionOccurs() {
        PasswordPolicyResponseDto expectedResponse = new PasswordPolicyResponseDto();
        expectedResponse.setMinLength(MIN_LENGTH);
        expectedResponse.setMaxLength(MAX_LENGTH);

        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(PasswordPolicyResponseDto.class))
                .thenReturn(Mono.error(new RuntimeException()));

        PasswordPolicyResponseDto passwordPolicy = userManagementClient.getPasswordPolicy();
        assertNull(passwordPolicy);
    }

    @Test
    void passwordPolicyReturnsNullWhenWebClientResponseExceptionOccurs() {
        PasswordPolicyResponseDto expectedResponse = new PasswordPolicyResponseDto();
        expectedResponse.setMinLength(MIN_LENGTH);
        expectedResponse.setMaxLength(MAX_LENGTH);

        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(PasswordPolicyResponseDto.class)).thenReturn(
                Mono.error(new WebClientResponseException(HttpStatus.SC_BAD_REQUEST, ACCOUNT_NAME, null, null, null)));

        PasswordPolicyResponseDto passwordPolicy = userManagementClient.getPasswordPolicy();
        assertNull(passwordPolicy);
    }

    @Test
    void selfCreateUser_Success() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");
        UserDetailsResponse expectedResponse = new UserDetailsResponse();
        expectedResponse.setEmail("test@example.com");

        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class)).thenReturn(Mono.just(expectedResponse));

        UserDetailsResponse response = userManagementClient.selfCreateUser(userDto, httpServletRequest);
        assertNotNull(response);
        assertEquals(expectedResponse.getEmail(), response.getEmail());
    }

    @Test
    void selfCreateUser_ThrowsWebClientResponseException() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");

        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class)).thenReturn(
                Mono.error(new WebClientResponseException(HttpStatus.SC_BAD_REQUEST, ACCOUNT_NAME, null, null, null)));

        Exception thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.selfCreateUser(userDto, httpServletRequest));
        assertNotNull(thrown.getMessage());
    }

    @Test
    void selfCreateUser_ThrowsException() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");

        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(new RuntimeException()));
        getUserErrorResponse();
        Exception thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.selfCreateUser(userDto, httpServletRequest));
        assertNotNull(thrown.getMessage());
    }

    private UserErrorResponse getUserErrorResponse() {
        UserErrorResponse userErrorResponse = new UserErrorResponse();
        userErrorResponse.setCode("Invalid request");
        userErrorResponse.setMessage("The request is invalid.");
        return userErrorResponse;
    }

    @Test
    void createFedratedUser_Success() {
        // Setup
        FederatedUserDto userRequest = new FederatedUserDto();
        userRequest.setUserName("testFedUser");
        userRequest.setEmail("feduser@test.com");

        UserDetailsResponse expectedResponse = new UserDetailsResponse();
        expectedResponse.setEmail("feduser@test.com");
        expectedResponse.setUserName("testFedUser");

        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        // Mock web client behavior
        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userRequest))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class)).thenReturn(Mono.just(expectedResponse));

        // Execute
        UserDetailsResponse response = userManagementClient.createFedratedUser(userRequest);

        // Verify
        assertNotNull(response);
        assertEquals(expectedResponse.getEmail(), response.getEmail());
        assertEquals(expectedResponse.getUserName(), response.getUserName());
    }

    @Test
    void createFedratedUser_ThrowsUnexpectedException() {
        // Setup
        FederatedUserDto userRequest = new FederatedUserDto();
        userRequest.setUserName("testUser");

        // Setup mock tenant properties
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);

        // Mock web client to throw unexpected exception
        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userRequest))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(new RuntimeException("Unexpected error")));

        // Execute & Verify
        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.createFedratedUser(userRequest));
        assertEquals(AuthorizationServerConstants.UNEXPECTED_ERROR, thrown.getError().getDescription());
    }

}