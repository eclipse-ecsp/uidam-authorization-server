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
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.AccountProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UserProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.UserNotFoundException;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.request.dto.FederatedUserDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserEvent;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.response.UserErrorResponse;
import org.eclipse.ecsp.oauth2.server.core.response.dto.PasswordPolicyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.UserEventResponse;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.service.impl.CaptchaServiceImpl;
import org.eclipse.ecsp.sql.multitenancy.TenantContext;
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
    private AuthorizationMetricsService authorizationMetricsService;

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
        userManagementClient = new UserManagementClient(tenantConfigurationService,
                                                        captchaService,
                                                        webClientMock,
                                                        authorizationMetricsService);
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
        assertEquals("Unable to validate username", thrown.getMessage());
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
        UserEventResponse mockResponse = UserEventResponse.builder()
            .userStatus("ACTIVE")
            .lockDurationMinutes(0)
            .message("Event recorded successfully")
            .build();
        when(responseSpecMock.bodyToMono(UserEventResponse.class)).thenReturn(Mono.just(mockResponse));

        UserEvent userEvent = new UserEvent();
        userEvent.setType("Login_Attempt");
        userEvent.setResult("Success");
        userEvent.setMessage("login sucessfully!");
        String userId = "6f452624-c4e3-40ff-ba29-fe9082705f50";
        UserEventResponse response = userManagementClient.addUserEvent(userEvent, userId);
        assertNotNull(response);
        assertEquals("ACTIVE", response.getUserStatus());
        assertEquals(0, response.getLockDurationMinutes());
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
        when(responseSpecMock.bodyToMono(UserEventResponse.class)).thenReturn(Mono.error(new RuntimeException()));

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
        Mockito.when(requestBodySpecMock.header(anyString(), anyString())).thenReturn(requestBodySpecMock);
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

    @Test
    void getUserDetailsByUsername_WebClientResponseExceptionWithIllegalStateOnErrorParsing() {
        // Test lines 215-229: WebClientResponseException with IllegalStateException when parsing error response
        String username = "testUser";
        String accountName = "testAccount";
        
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);
        
        // Create a WebClientResponseException that will throw IllegalStateException when parsing response body
        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.BAD_REQUEST);
        when(wcException.getResponseBodyAs(UserErrorResponse.class))
                .thenThrow(new IllegalStateException("Could not decode response body"));
        
        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));
        
        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername(username, accountName));
        
        assertNotNull(thrown);
        assertNotNull(thrown.getError());
    }

    @Test
    void getUserDetailsByUsername_GenericException() {
        // Test lines 229+: Generic Exception handling
        String username = "testUser";
        String accountName = "testAccount";
        
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);
        
        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(new IllegalArgumentException("Unexpected error")));
        
        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername(username, accountName));
        
        assertNotNull(thrown);
        assertEquals("server_error", thrown.getError().getErrorCode());
    }

    @Test
    void sendUserResetPasswordNotification_WebClientResponseException() {
        // Test lines 304-309: Password recovery notification exception handling
        String username = "testUser";
        String accountName = "testAccount";
        
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);
        
        String responseBody = "Error processing password recovery";
        WebClientResponseException wcException = WebClientResponseException.create(
                HttpStatus.SC_INTERNAL_SERVER_ERROR, "Internal Server Error",
                null, responseBody.getBytes(), null);
        
        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.toBodilessEntity())
                .thenReturn(Mono.error(wcException));
        
        Exception thrown = assertThrows(Exception.class,
                () -> userManagementClient.sendUserResetPasswordNotification(username, accountName));
        
        assertNotNull(thrown);
    }

    @Test
    void extractMessage_WithValidInput() {
        // Test lines 396-406: extractMessage method with valid input
        final String username = "testUser";
        final String accountName = "testAccount";
        
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);
        
        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage(" Error ='{ Error ='password validation failed', parameters=test}");
        
        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.BAD_REQUEST);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);
        
        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));
        
        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername(username, accountName));
        
        assertNotNull(thrown);
        // handleUserFetchError returns server_error for BAD_REQUEST, not BAD_REQUEST itself
        // extractMessage is only used in handleWebClientResponseException (for user creation), 
        // not in handleUserFetchError (for user fetch)
        assertEquals("server_error", thrown.getError().getErrorCode());
        assertEquals(" Error ='{ Error ='password validation failed', parameters=test}", 
                thrown.getError().getDescription());
    }

    @Test
    void handleUserFetchError_NotFoundStatus() {
        // Test lines 435-453: NOT_FOUND status handling
        final String username = "nonExistentUser";
        final String accountName = "testAccount";
        
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);
        
        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setCode("RESOURCE_NOT_FOUND");
        
        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.NOT_FOUND);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);
        
        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));
        
        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername(username, accountName));
        
        assertNotNull(thrown);
        // handleUserFetchError returns server_error for NOT_FOUND if errorResponse has no message
        assertEquals("server_error", thrown.getError().getErrorCode());
        assertEquals("Unable to validate username", thrown.getError().getDescription());
    }

    @Test
    void handleUserFetchError_MethodNotAllowedStatus() {
        // Test lines 435-453: METHOD_NOT_ALLOWED status handling
        String username = "testUser";
        String accountName = "testAccount";
        
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);
        
        UserErrorResponse errorResponse = new UserErrorResponse();
        
        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.METHOD_NOT_ALLOWED);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);
        
        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));
        
        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername(username, accountName));
        
        assertNotNull(thrown);
        // handleUserFetchError returns server_error for METHOD_NOT_ALLOWED with no message
        assertEquals("server_error", thrown.getError().getErrorCode());
        assertEquals("Unable to validate username", thrown.getError().getDescription());
    }

    @Test
    void handleUserFetchError_ConflictStatus() {
        // Test lines 435-453: CONFLICT status handling
        String username = "testUser";
        String accountName = "testAccount";
        
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);
        
        UserErrorResponse errorResponse = new UserErrorResponse();
        
        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.CONFLICT);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);
        
        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));
        
        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername(username, accountName));
        
        assertNotNull(thrown);
        // handleUserFetchError returns server_error for CONFLICT with no message
        assertEquals("server_error", thrown.getError().getErrorCode());
        assertEquals("Unable to validate username", thrown.getError().getDescription());
    }

    @Test
    void handleUserFetchError_BadRequestWithPasswordError() {
        // Test lines 435-453: BAD_REQUEST with password error in message
        final String username = "testUser";
        final String accountName = "testAccount";
        
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);
        
        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage(" Error ='{ Error ='password validation failed', parameters=test}");
        
        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.BAD_REQUEST);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);
        
        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));
        
        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername(username, accountName));
        
        assertNotNull(thrown);
        // handleUserFetchError returns server_error for BAD_REQUEST (this method doesn't parse password errors)
        assertEquals("server_error", thrown.getError().getErrorCode());
        assertEquals(" Error ='{ Error ='password validation failed', parameters=test}", 
                thrown.getError().getDescription());
    }

    @Test
    void handleUserFetchError_ServerError() {
        // Test lines 435-453: Default server error handling
        String username = "testUser";
        String accountName = "testAccount";
        
        TenantProperties mockTenantProperties = createMockTenantProperties();
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mockTenantProperties);
        
        WebClientResponseException wcException = WebClientResponseException.create(
                HttpStatus.SC_SERVICE_UNAVAILABLE, "Service Unavailable",
                null, new byte[0], null);
        
        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));
        
        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername(username, accountName));
        
        assertNotNull(thrown);
        assertEquals("server_error", thrown.getError().getErrorCode());
    }

    // ─────────────── MFA Tests ────────────────────────────────────────────────

    private TenantProperties createMockTenantPropertiesWithMfa() {
        TenantProperties props = createMockTenantProperties();
        HashMap<String, String> externalUrls = new HashMap<>(props.getExternalUrls());
        externalUrls.put(AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_ENROLL_INITIATE,
                "/v1/users/{username}/mfa/enroll");
        externalUrls.put(AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_ENROLL_ACTIVATE,
                "/v1/users/{username}/mfa/activate");
        externalUrls.put(AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_STATUS,
                "/v1/users/{username}/mfa/status");
        externalUrls.put(AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_SECRET,
                "/v1/users/{username}/mfa/secret");
        externalUrls.put(AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_REVOKE,
                "/v1/users/{username}/mfa/revoke");
        externalUrls.put(AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_RECOVERY_SEND,
                "/v1/users/{username}/mfa/recovery/send");
        externalUrls.put(AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_RECOVERY_VERIFY,
                "/v1/users/{username}/mfa/recovery/verify");
        externalUrls.put(AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_BACKUP_CODES_GENERATE,
                "/v1/users/{username}/mfa/backup-codes/generate");
        externalUrls.put(AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_BACKUP_CODES_VERIFY,
                "/v1/users/{username}/mfa/backup-codes/verify");
        props.setExternalUrls(externalUrls);
        return props;
    }

    @Test
    void testInitiateMfaEnrollment_success() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto dto =
                new org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto(
                        "SECRET", "otpauth://...", "SECR ET");

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(
                org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto.class))
                .thenReturn(Mono.just(dto));

        org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto result =
                userManagementClient.initiateMfaEnrollment("testuser");

        assertNotNull(result);
        assertEquals("SECRET", result.secret());
    }

    @Test
    void testInitiateMfaEnrollment_throwsOnError() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(
                org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto.class))
                .thenReturn(Mono.error(new RuntimeException("network error")));

        assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,
                () -> userManagementClient.initiateMfaEnrollment("testuser"));
    }

    @Test
    void testActivateMfaEnrollment_success() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.toBodilessEntity()).thenReturn(Mono.just(ResponseEntity.ok().build()));

        userManagementClient.activateMfaEnrollment("testuser");
        verify(webClientMock).method(any());
    }

    @Test
    void testActivateMfaEnrollment_throwsOnError() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.toBodilessEntity()).thenReturn(Mono.error(new RuntimeException("network error")));

        assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,
                () -> userManagementClient.activateMfaEnrollment("testuser"));
    }

    @Test
    void testGetMfaStatus_success() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        org.eclipse.ecsp.oauth2.server.core.response.dto.MfaStatusResponseDto statusDto =
                new org.eclipse.ecsp.oauth2.server.core.response.dto.MfaStatusResponseDto(
                        true, "ACTIVE", false);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.accept(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(
                org.eclipse.ecsp.oauth2.server.core.response.dto.MfaStatusResponseDto.class))
                .thenReturn(Mono.just(statusDto));

        java.util.Optional<org.eclipse.ecsp.oauth2.server.core.response.dto.MfaStatusResponseDto> result =
                userManagementClient.getMfaStatus("testuser");

        assertNotNull(result);
        assertEquals(true, result.isPresent());
    }

    @Test
    void testGetMfaStatus_returnsEmpty_on404() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.accept(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(
                org.eclipse.ecsp.oauth2.server.core.response.dto.MfaStatusResponseDto.class))
                .thenReturn(Mono.error(org.springframework.web.reactive.function.client.WebClientResponseException
                        .create(404, "Not Found", null, new byte[0], null)));

        java.util.Optional<org.eclipse.ecsp.oauth2.server.core.response.dto.MfaStatusResponseDto> result =
                userManagementClient.getMfaStatus("testuser");

        assertEquals(false, result.isPresent());
    }

    @Test
    void testGetMfaStatus_returnsEmpty_onGenericError() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.accept(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(
                org.eclipse.ecsp.oauth2.server.core.response.dto.MfaStatusResponseDto.class))
                .thenReturn(Mono.error(new RuntimeException("network error")));

        java.util.Optional<org.eclipse.ecsp.oauth2.server.core.response.dto.MfaStatusResponseDto> result =
                userManagementClient.getMfaStatus("testuser");

        assertEquals(false, result.isPresent());
    }

    @Test
    void testGetMfaSecret_success() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.accept(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(String.class)).thenReturn(Mono.just("BASE32SECRET"));

        java.util.Optional<String> result = userManagementClient.getMfaSecret("testuser");

        assertNotNull(result);
        assertEquals("BASE32SECRET", result.orElse(null));
    }

    @Test
    void testGetMfaSecret_returnsEmpty_onError() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.accept(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(String.class)).thenReturn(
                Mono.error(org.springframework.web.reactive.function.client.WebClientResponseException
                        .create(404, "Not Found", null, new byte[0], null)));

        java.util.Optional<String> result = userManagementClient.getMfaSecret("testuser");

        assertEquals(false, result.isPresent());
    }

    @Test
    void testRevokeMfaEnrollment_success() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.toBodilessEntity()).thenReturn(Mono.just(ResponseEntity.ok().build()));

        userManagementClient.revokeMfaEnrollment("testuser");
        verify(webClientMock).method(any());
    }

    @Test
    void testRevokeMfaEnrollment_throwsOnError() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.toBodilessEntity()).thenReturn(Mono.error(new RuntimeException("error")));

        assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,
                () -> userManagementClient.revokeMfaEnrollment("testuser"));
    }

    @Test
    void testSendMfaRecoveryKey_success() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.onStatus(any(), any())).thenReturn(responseSpecMock);
        when(responseSpecMock.toBodilessEntity()).thenReturn(Mono.just(ResponseEntity.ok().build()));

        userManagementClient.sendMfaRecoveryKey("testuser");
        verify(webClientMock).method(any());
    }

    @Test
    void testSendMfaRecoveryKey_throwsOnError() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.onStatus(any(), any())).thenReturn(responseSpecMock);
        when(responseSpecMock.toBodilessEntity()).thenReturn(Mono.error(new RuntimeException("error")));

        assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,
                () -> userManagementClient.sendMfaRecoveryKey("testuser"));
    }

    @Test
    void testVerifyMfaRecoveryKey_returnsTrue() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.bodyValue(any())).thenReturn(requestHeadersSpecMock);
        when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(Boolean.class)).thenReturn(Mono.just(Boolean.TRUE));

        boolean result = userManagementClient.verifyMfaRecoveryKey("testuser", "ABC123");

        assertEquals(true, result);
    }

    @Test
    void testVerifyMfaRecoveryKey_returnsFalse_onError() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.bodyValue(any())).thenReturn(requestHeadersSpecMock);
        when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(Boolean.class)).thenReturn(Mono.error(new RuntimeException("error")));

        boolean result = userManagementClient.verifyMfaRecoveryKey("testuser", "WRONG");

        assertEquals(false, result);
    }

    @Test
    void testVerifyMfaRecoveryKey_returnsFalse_whenResultIsNull() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.bodyValue(any())).thenReturn(requestHeadersSpecMock);
        when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(Boolean.class)).thenReturn(Mono.empty());

        boolean result = userManagementClient.verifyMfaRecoveryKey("testuser", "ABC123");

        assertEquals(false, result);
    }

    @Test
    void testGenerateMfaBackupCodes_success() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto dto =
                new org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto(
                        java.util.List.of("CODE1", "CODE2"), 2);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(
                org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto.class))
                .thenReturn(Mono.just(dto));

        org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto result =
                userManagementClient.generateMfaBackupCodes("testuser");

        assertNotNull(result);
        assertEquals(2, result.count());
    }

    @Test
    void testGenerateMfaBackupCodes_throwsOnError() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString(), any(Object.class))).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(
                org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto.class))
                .thenReturn(Mono.error(new RuntimeException("error")));

        assertThrows(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class,
                () -> userManagementClient.generateMfaBackupCodes("testuser"));
    }

    @Test
    void testVerifyMfaBackupCode_success() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto dto =
                new org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto(
                        true, 4, false);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.bodyValue(any())).thenReturn(requestHeadersSpecMock);
        when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(
                org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto.class))
                .thenReturn(Mono.just(dto));

        org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto result =
                userManagementClient.verifyMfaBackupCode("testuser", "CODE1");

        assertNotNull(result);
        assertEquals(true, result.valid());
    }

    @Test
    void testVerifyMfaBackupCode_returnsInvalid_onError() {
        TenantProperties mfaProps = createMockTenantPropertiesWithMfa();
        when(tenantConfigurationService.getTenantProperties()).thenReturn(mfaProps);
        when(tenantConfigurationService.getTenantProperties("ecsp")).thenReturn(mfaProps);

        when(webClientMock.method(any())).thenReturn(requestBodyUriSpecMock);
        when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        when(requestBodySpecMock.bodyValue(any())).thenReturn(requestHeadersSpecMock);
        when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        when(responseSpecMock.bodyToMono(
                org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto.class))
                .thenReturn(Mono.error(new RuntimeException("error")));

        org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto result =
                userManagementClient.verifyMfaBackupCode("testuser", "WRONG");

        assertNotNull(result);
        assertEquals(false, result.valid());
        assertEquals(0, result.remainingBackupCodes());
    }

    // ─── handleUserFetchError branch tests ───────────────────────────────────

    @Test
    void handleUserFetchError_ForbiddenWithTemporaryLock() {
        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage("Account temporarily locked for 15 minutes");
        errorResponse.setIsTemporaryLock(Boolean.TRUE);
        errorResponse.setMinutesLeftToUnlock(15L);

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.FORBIDDEN);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername("testUser", "testAccount"));

        assertNotNull(thrown);
        assertEquals("USER_TEMPORARILY_BLOCKED", thrown.getError().getErrorCode());
    }

    @Test
    void handleUserFetchError_ForbiddenWithAccountMessage() {
        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage("Your account has been disabled");
        errorResponse.setIsTemporaryLock(Boolean.FALSE);

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.FORBIDDEN);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername("testUser", "testAccount"));

        assertNotNull(thrown);
        assertEquals("ACCOUNT_NOT_FOUND", thrown.getError().getErrorCode());
    }

    @Test
    void handleUserFetchError_ForbiddenWithGenericMessage() {
        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage("User is not active");
        errorResponse.setIsTemporaryLock(Boolean.FALSE);

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.FORBIDDEN);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername("testUser", "testAccount"));

        assertNotNull(thrown);
        assertEquals("USER_NOT_ACTIVE", thrown.getError().getErrorCode());
    }

    @Test
    void handleUserFetchError_NotFoundWithMessage() {
        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage("User not found in the system");

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.NOT_FOUND);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername("testUser", "testAccount"));

        assertNotNull(thrown);
        assertEquals("USER_NOT_FOUND", thrown.getError().getErrorCode());
    }

    @Test
    void handleUserFetchError_OtherStatusWithMessage() {
        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage("Internal server error occurred");

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.GET)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString(), anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.accept(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.getUserDetailsByUsername("testUser", "testAccount"));

        assertNotNull(thrown);
        assertEquals("server_error", thrown.getError().getErrorCode());
        assertEquals("Internal server error occurred", thrown.getError().getDescription());
    }

    // ─── handleWebClientResponseException branch tests ──────────────────────

    @Test
    void selfCreateUser_NotFound_ShouldThrowResourceNotFound() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");

        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage("Resource not found");

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.NOT_FOUND);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.selfCreateUser(userDto, httpServletRequest));

        assertEquals("RESOURCE_NOT_FOUND", thrown.getError().getErrorCode());
    }

    @Test
    void selfCreateUser_MethodNotAllowed_ShouldThrowServerError() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");

        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage("Method not allowed");

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.METHOD_NOT_ALLOWED);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.selfCreateUser(userDto, httpServletRequest));

        assertEquals("server_error", thrown.getError().getErrorCode());
    }

    @Test
    void selfCreateUser_Conflict_ShouldThrowRecordAlreadyExists() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");

        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage("User already exists");

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.CONFLICT);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.selfCreateUser(userDto, httpServletRequest));

        assertEquals("RECORD_ALREADY_EXISTS", thrown.getError().getErrorCode());
    }

    @Test
    void selfCreateUser_BadRequestWithPasswordError_ShouldReturnInvalidPassword() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");

        UserErrorResponse errorResponse = new UserErrorResponse();
        // extractMessage extracts between " Error ='{ Error ='" and "', parameters="
        // resulting text must contain "Password" (capital P) to trigger INVALID_PASSWORD
        errorResponse.setMessage(" Error ='{ Error ='Password must be stronger', parameters=none}");

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.BAD_REQUEST);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.selfCreateUser(userDto, httpServletRequest));

        assertEquals("BAD_REQUEST", thrown.getError().getErrorCode());
        assertEquals(AuthorizationServerConstants.INVALID_PASSWORD, thrown.getError().getDescription());
    }

    @Test
    void selfCreateUser_BadRequestWithNonPasswordError_ShouldReturnBadRequest() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");

        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage(" Error ='{ Error ='username invalid', parameters=none}");

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.BAD_REQUEST);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.selfCreateUser(userDto, httpServletRequest));

        assertEquals("BAD_REQUEST", thrown.getError().getErrorCode());
    }

    @Test
    void selfCreateUser_OtherStatus_ShouldReturnServerError() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");

        UserErrorResponse errorResponse = new UserErrorResponse();
        errorResponse.setMessage("Internal error");

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.selfCreateUser(userDto, httpServletRequest));

        assertEquals("server_error", thrown.getError().getErrorCode());
    }

    @Test
    void selfCreateUser_WebClientResponseException_NullBody_ShouldReturnServerError() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.BAD_REQUEST);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(null);

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.selfCreateUser(userDto, httpServletRequest));

        assertEquals("server_error", thrown.getError().getErrorCode());
    }

    @Test
    void selfCreateUser_WebClientResponseException_IllegalStateParsingBody_ShouldReturnServerError() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.BAD_REQUEST);
        when(wcException.getResponseBodyAs(UserErrorResponse.class))
                .thenThrow(new IllegalStateException("Could not decode"));

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.selfCreateUser(userDto, httpServletRequest));

        assertEquals("server_error", thrown.getError().getErrorCode());
    }

    @Test
    void extractMessage_withNoPatternMatch_shouldReturnNull() {
        UserDto userDto = new UserDto();
        userDto.setUserName("testUser");

        UserErrorResponse errorResponse = new UserErrorResponse();
        // Message does not match the extractMessage pattern
        errorResponse.setMessage("simple error message without pattern");

        WebClientResponseException wcException = Mockito.mock(WebClientResponseException.class);
        when(wcException.getStatusCode()).thenReturn(org.springframework.http.HttpStatus.BAD_REQUEST);
        when(wcException.getResponseBodyAs(UserErrorResponse.class)).thenReturn(errorResponse);

        Mockito.when(webClientMock.method(HttpMethod.POST)).thenReturn(requestBodyUriSpecMock);
        Mockito.when(requestBodyUriSpecMock.uri(anyString())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.header(anyString(), any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.contentType(any())).thenReturn(requestBodySpecMock);
        Mockito.when(requestBodySpecMock.bodyValue(userDto))
                .thenReturn((WebClient.RequestHeadersSpec) requestHeadersSpecMock);
        Mockito.when(requestHeadersSpecMock.retrieve()).thenReturn(responseSpecMock);
        Mockito.when(responseSpecMock.bodyToMono(UserDetailsResponse.class))
                .thenReturn(Mono.error(wcException));

        OAuth2AuthenticationException thrown = assertThrows(OAuth2AuthenticationException.class,
                () -> userManagementClient.selfCreateUser(userDto, httpServletRequest));

        assertEquals("BAD_REQUEST", thrown.getError().getErrorCode());
        // extractMessage returns null, so INVALID_PASSWORD is NOT returned, falls back to UNEXPECTED_ERROR
        assertEquals(AuthorizationServerConstants.UNEXPECTED_ERROR, thrown.getError().getDescription());
    }
}