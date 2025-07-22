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

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.eclipse.ecsp.oauth2.server.core.common.UpdatePasswordData;
import org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.PasswordRecoveryException;
import org.eclipse.ecsp.oauth2.server.core.exception.UidamApplicationException;
import org.eclipse.ecsp.oauth2.server.core.exception.UserNotFoundException;
import org.eclipse.ecsp.oauth2.server.core.interceptor.ClientAddCorrelationIdInterceptor;
import org.eclipse.ecsp.oauth2.server.core.request.dto.BaseUserDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.FederatedUserDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserEvent;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.response.UserErrorResponse;
import org.eclipse.ecsp.oauth2.server.core.response.dto.PasswordPolicyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.service.impl.CaptchaServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Collections;
import java.util.Objects;
import java.util.UUID;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.INVALID_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_ADD_USER_EVENTS_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_CREATE_FEDRATED_USER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_PASSWORD_POLICY_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_SELF_CREATE_USER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_BY_USERNAME_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_MANAGEMENT_ENV;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_RECOVERY_NOTIF_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_RESET_PASSWORD_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.UNEXPECTED_ERROR;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.USER_ALREADY_EXISTS_PLEASE_TRY_AGAIN;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ACCOUNT_NAME_HEADER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.EMPTY_STRING;
import static org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils.obtainRecaptchaResponse;
import static org.eclipse.ecsp.oauth2.server.core.utils.RequestResponseLogger.logRequest;
import static org.eclipse.ecsp.oauth2.server.core.utils.RequestResponseLogger.logResponse;

/**
 * The UserManagementClient class manages connections with the User Management Service. It uses a WebClient to make HTTP
 * requests and an ObjectMapper to serialize and deserialize JSON.
 */
@Component
public class UserManagementClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserManagementClient.class);

    private ObjectMapper objectMapper = new ObjectMapper();

    private final TenantConfigurationService tenantConfigurationService;
    private final CaptchaServiceImpl captchaServiceImpl;
    private final WebClient webClient;

    /**
     * Constructor for UserManagementClient. It initializes the tenant configuration service for dynamic tenant
     * resolution.
     *
     * @param tenantConfigurationService the service to retrieve tenant properties from
     * @param captchaServiceImpl the captcha service implementation
     */
    @Autowired
    public UserManagementClient(TenantConfigurationService tenantConfigurationService,
            CaptchaServiceImpl captchaServiceImpl) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.captchaServiceImpl = captchaServiceImpl;
        this.webClient = null; // Will use dynamic WebClient creation
    }

    /**
     * Constructor for UserManagementClient with WebClient injection (mainly for testing).
     *
     * @param tenantConfigurationService the service to retrieve tenant properties from
     * @param captchaServiceImpl the captcha service implementation
     * @param webClient the WebClient to use for HTTP requests
     */
    public UserManagementClient(TenantConfigurationService tenantConfigurationService,
            CaptchaServiceImpl captchaServiceImpl, WebClient webClient) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.captchaServiceImpl = captchaServiceImpl;
        this.webClient = webClient;
    }

    /**
     * This method is called after the constructor. It configures the ObjectMapper to include non-null properties and
     * not fail on unknown properties.
     */
    @PostConstruct
    private void init() {
        objectMapper.setSerializationInclusion(Include.NON_NULL)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    /**
     * Get the current tenant's properties and create a WebClient for the current tenant.
     *
     * @return WebClient configured for the current tenant
     */
    private WebClient getWebClientForCurrentTenant() {
        // If WebClient is injected (for testing), use it directly
        if (webClient != null) {
            return webClient;
        }

        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        if (tenantProperties == null) {
            throw new IllegalStateException("No tenant properties found for current tenant");
        }

        String baseUrl = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_USER_MANAGEMENT_ENV);
        if (baseUrl == null) {
            throw new IllegalStateException("No user management base URL configured for current tenant");
        }

        return WebClient.builder().baseUrl(baseUrl)
                .filter(ClientAddCorrelationIdInterceptor.addCorrelationIdAndContentType()).filter(logRequest())
                .filter(logResponse()).build();
    }

    /**
     * Get the current tenant's properties.
     *
     * @return the tenant properties for the current tenant
     */
    private TenantProperties getCurrentTenantProperties() {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        if (tenantProperties == null) {
            throw new IllegalStateException("No tenant properties found for current tenant");
        }
        return tenantProperties;
    }

    /**
     * This method fetches the user details from the User Management Service. It makes a GET request to the User
     * Management Service and retrieves the user details. If an error occurs during the process, it throws an
     * OAuth2AuthenticationException.
     *
     * @param username the username of the user whose details are to be fetched
     * @param accountName the account name of the user
     * @return the user details as a UserDetailsResponse object, or null if an error occurs
     */
    public UserDetailsResponse getUserDetailsByUsername(String username, String accountName) {
        LOGGER.info("Fetching user details for username {} from user-mgmt account Name {}", username, accountName);

        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();

            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_USER_BY_USERNAME_ENDPOINT);
            if (!StringUtils.hasText(accountName)) {
                accountName = tenantProperties.getAccount().getAccountName();
            }
            LOGGER.debug("Account name {}", accountName);
            UserDetailsResponse userDetailsResponse = null;

            userDetailsResponse = currentWebClient.method(HttpMethod.GET).uri(uri, username)
                    .header(ACCOUNT_NAME_HEADER, accountName).accept(MediaType.APPLICATION_JSON).retrieve()
                    .bodyToMono(UserDetailsResponse.class).block();
            userDetailsResponse = objectMapper.convertValue(userDetailsResponse,
                    new TypeReference<UserDetailsResponse>() {
                    });
            LOGGER.debug("User details response received for username {} from user-mgmt", username);
            return userDetailsResponse;
        } catch (WebClientResponseException ex) {
            LOGGER.error("Web client error while fetching user details for username {} from user-mgmt, ex: {}",
                    username, ex);
            UserErrorResponse userErrorResponse = null;
            try {
                userErrorResponse = ex.getResponseBodyAs(UserErrorResponse.class);
            } catch (IllegalStateException e) {
                LOGGER.debug("Could not decode response body: {}", e.getMessage());
            }
            String errorCode;
            String errorDesc = "";
            if (userErrorResponse != null) {
                if (HttpStatus.NOT_FOUND == ex.getStatusCode()) {
                    errorCode = CustomOauth2TokenGenErrorCodes.USER_NOT_FOUND.name();
                    errorDesc = userErrorResponse.getMessage();
                } else if (HttpStatus.FORBIDDEN == ex.getStatusCode()) {
                    errorCode = CustomOauth2TokenGenErrorCodes.USER_NOT_ACTIVE.name();
                    errorDesc = CustomOauth2TokenGenErrorCodes.USER_NOT_ACTIVE.getDescription();
                } else {
                    errorCode = OAuth2ErrorCodes.SERVER_ERROR;
                    errorDesc = userErrorResponse.getMessage();
                }

            } else {
                errorCode = OAuth2ErrorCodes.SERVER_ERROR;
                errorDesc = "Unable to validate " + OAuth2ParameterNames.USERNAME;
            }
            OAuth2Error error = new OAuth2Error(errorCode, errorDesc, null);
            throw new OAuth2AuthenticationException(error);
        } catch (Exception ex) {
            LOGGER.error("error while fetching user details for username {} from user-mgmt, ex: {}", username, ex);
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "Unable to validate " + OAuth2ParameterNames.USERNAME, null);
            throw new OAuth2AuthenticationException(error);
        }
    }

    /**
     * This method adds a user event to the User Management Service. It makes a POST request to the User Management
     * Service to add the user event. If an error occurs during the process, it throws an OAuth2AuthenticationException.
     *
     * @param userEvent the user event to be added
     * @param userId the ID of the user for whom the event is to be added
     * @return a string response from the User Management Service
     */
    public String addUserEvent(UserEvent userEvent, String userId) {
        LOGGER.debug("Adding user event {} details for userId {} to user-mgmt", userEvent.getType(), userId);

        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();

            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_ADD_USER_EVENTS_ENDPOINT);
            String response;

            response = currentWebClient.method(HttpMethod.POST).uri(uri, userId)
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .contentType(MediaType.APPLICATION_JSON).bodyValue(userEvent).retrieve().bodyToMono(String.class)
                    .block();
            return response;
        } catch (Exception ex) {
            LOGGER.error("error while processing user event details for userId {} from user-mgmt, ex: {}", userId,
                    ex.getMessage());
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "failed to process user event", null);
            throw new OAuth2AuthenticationException(error);
        }
    }

    /**
     * This method sends a user password recovery link to the User Management Service. It makes a POST request to the
     * User Management Service to send the password recovery link. If an error occurs during the process, it throws an
     * appropriate exception.
     *
     * @param username the username of the user who needs to recover their password
     * @param accountName the account name of the user
     */
    public void sendUserResetPasswordNotification(String username, String accountName) {
        LOGGER.info("sending user password recovery link details for userid {} to user-mgmt", username);

        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();

            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_USER_RECOVERY_NOTIF_ENDPOINT);

            currentWebClient.method(HttpMethod.POST).uri(uri, username)
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .header(ACCOUNT_NAME_HEADER, accountName).contentType(MediaType.APPLICATION_JSON).retrieve()
                    .toBodilessEntity().block();
        } catch (WebClientResponseException ex) {
            if (ex.getStatusCode().isSameCodeAs(HttpStatus.NOT_FOUND)) {
                throw new UserNotFoundException(IgniteOauth2CoreConstants.USER_DETAILS_NOT_FOUND);
            }
            String exceptionMessage = ex.getResponseBodyAsString();
            LOGGER.error(
                    "error while processing user recovery notification to "
                            + "reset password for userid {} from user-mgmt, exceptionMessage: {}",
                    username, exceptionMessage);
            throw new PasswordRecoveryException(ex.getResponseBodyAsString());
        }
    }

    /**
     * This method updates a user's password using a recovery secret. It makes a POST request to the User Management
     * Service to update the user's password. If an error occurs during the process, it throws a
     * UidamApplicationException.
     *
     * @param updatePasswordData the data needed to update the user's password
     * @return a string response from the User Management Service
     */
    public String updateUserPasswordUsingRecoverySecret(UpdatePasswordData updatePasswordData) {
        LOGGER.info("updating user password using recovery secret details to user-mgmt");
        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();

            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_USER_RESET_PASSWORD_ENDPOINT);
            String response = null;
            response = currentWebClient.method(HttpMethod.POST).uri(uri)
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .contentType(MediaType.APPLICATION_JSON).bodyValue(updatePasswordData).retrieve()
                    .bodyToMono(String.class).block();
            return response;
        } catch (WebClientResponseException ex) {
            LOGGER.error("error while processing user password recovery using recovery secret from user-mgmt, ex: {0}",
                    ex);
            if (HttpStatus.BAD_REQUEST.equals(ex.getStatusCode())) {
                throw new UidamApplicationException(ex.getResponseBodyAsString());
            } else {
                throw new UidamApplicationException("failed to process request");
            }
        }
    }

    /**
     * This method is used to create self user in the User Management Service.
     *
     * @param userDto used as body for the request.
     * @param request HttpServletRequest
     * @return userDetailsResponse received from User management service.
     */
    public UserDetailsResponse selfCreateUser(UserDto userDto, HttpServletRequest request) {
        LOGGER.debug("## selfCreateUser - START");
        LOGGER.info("Self Create user call for username {} to user-mgmt", userDto.getUserName());

        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();

            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_SELF_CREATE_USER);
            userDto = validateCaptchaAndAddRequiredParams(userDto, request);
            UserDetailsResponse userDetailsResponse = currentWebClient.method(HttpMethod.POST).uri(uri)
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .contentType(MediaType.APPLICATION_JSON).bodyValue(userDto).retrieve()
                    .bodyToMono(UserDetailsResponse.class).block();
            return objectMapper.convertValue(userDetailsResponse, new TypeReference<UserDetailsResponse>() {
            });
        } catch (WebClientResponseException ex) {
            LOGGER.error("Webclient Exception while creating user for username {} from user-mgmt, ex: ",
                    userDto.getUserName(), ex);
            handleWebClientResponseException(ex, userDto);
        } catch (Exception ex) {
            LOGGER.error("Error while creating user for username {} from user-mgmt, ex: ", userDto.getUserName(), ex);
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, UNEXPECTED_ERROR, null);
            throw new OAuth2AuthenticationException(error);
        }
        LOGGER.debug("## selfCreateUser - END");
        return null;
    }

    private UserDto validateCaptchaAndAddRequiredParams(UserDto userDto, HttpServletRequest request) {
        LOGGER.debug("Captcha Validation started for user: " + userDto.getUserName());
        String recaptchaResponse = obtainRecaptchaResponse(request);
        recaptchaResponse = (recaptchaResponse != null) ? recaptchaResponse : EMPTY_STRING;

        if (StringUtils.hasText(recaptchaResponse)) {
            captchaServiceImpl.processResponse(recaptchaResponse, request);
        }
        addRequiredParameters(userDto);
        LOGGER.debug("## validateCaptchaAndAddRequiredParams - END");
        return userDto;
    }

    private String extractMessage(String input) {
        String startToken = " Error ='{ Error ='";
        String endToken = "', parameters=";

        int startIndex = input.indexOf(startToken) + startToken.length();
        int endIndex = input.indexOf(endToken);

        if (startIndex >= 0 && endIndex > startIndex) {
            return input.substring(startIndex, endIndex);
        }
        return null;
    }

    private void addRequiredParameters(UserDto userDto) {
        LOGGER.debug("## addRequiredParameters - START");
        if (CollectionUtils.isEmpty(userDto.getRoles())) {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            userDto.setRoles(Collections.singletonList(tenantProperties.getUser().getDefaultRole()));
        }
        if (!StringUtils.hasText(userDto.getUserName())) {
            userDto.setUserName(userDto.getEmail());
        }

        LOGGER.debug("## addRequiredParameters - END");
    }

    private <T extends BaseUserDto> void handleWebClientResponseException(WebClientResponseException ex, T userDto) {
        LOGGER.error("Web client error while creating user for username {} from user-mgmt, ex: ", userDto.getUserName(),
                ex);
        UserErrorResponse userErrorResponse = null;
        try {
            userErrorResponse = ex.getResponseBodyAs(UserErrorResponse.class);
        } catch (IllegalStateException e) {
            LOGGER.debug("Could not decode response body: {}", e.getMessage());
        }
        String errorCode;
        String errorDesc = UNEXPECTED_ERROR;

        if (userErrorResponse != null) {
            if (HttpStatus.NOT_FOUND == ex.getStatusCode()) {
                errorCode = CustomOauth2TokenGenErrorCodes.RESOURCE_NOT_FOUND.name();
            } else if (HttpStatus.METHOD_NOT_ALLOWED == ex.getStatusCode()) {
                errorCode = OAuth2ErrorCodes.SERVER_ERROR;
                errorDesc = UNEXPECTED_ERROR;
            } else if (HttpStatus.CONFLICT == ex.getStatusCode()) {
                errorCode = CustomOauth2TokenGenErrorCodes.RECORD_ALREADY_EXISTS.name();
                errorDesc = USER_ALREADY_EXISTS_PLEASE_TRY_AGAIN;
            } else if (HttpStatus.BAD_REQUEST == ex.getStatusCode()) {
                errorCode = CustomOauth2TokenGenErrorCodes.BAD_REQUEST.name();
                if (userErrorResponse.getMessage() != null
                        && this.extractMessage(userErrorResponse.getMessage()) != null
                        && Objects.requireNonNull(this.extractMessage(userErrorResponse.getMessage()))
                                .contains(PASSWORD)) {
                    errorDesc = INVALID_PASSWORD;
                }
            } else {
                errorCode = OAuth2ErrorCodes.SERVER_ERROR;
            }
        } else {
            errorCode = OAuth2ErrorCodes.SERVER_ERROR;
        }

        OAuth2Error error = new OAuth2Error(errorCode, errorDesc, null);
        LOGGER.debug("## handleWebClientResponseException - END");
        throw new OAuth2AuthenticationException(error);
    }

    /**
     * Fetches the password policy from the User Management Service. This method makes a GET request to the User
     * Management Service to retrieve the password policy. If an error occurs during the process, it throws an
     * OAuth2AuthenticationException.
     *
     * @return PasswordPolicyResponseDto containing the password policy details
     * @throws OAuth2AuthenticationException if there is an error fetching the password policy
     */
    public PasswordPolicyResponseDto getPasswordPolicy() {
        LOGGER.debug("## getPasswordPolicy - START");

        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();

            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_PASSWORD_POLICY_ENDPOINT);
            PasswordPolicyResponseDto password = null;

            password = currentWebClient.method(HttpMethod.GET).uri(uri).accept(MediaType.APPLICATION_JSON).retrieve()
                    .bodyToMono(PasswordPolicyResponseDto.class).block();
            LOGGER.debug("Password policy response received");
            return password;
        } catch (WebClientResponseException ex) {
            LOGGER.error("Web client error while fetching password policy", ex);
        } catch (Exception ex) {
            LOGGER.error("Error while fetching password policy", ex);
        }
        LOGGER.debug("## getPasswordPolicy - END");
        return null;
    }

    /**
     * Creates a federated user in the User Management Service. This method makes a POST request to create a new
     * federated user.
     *
     * @param userRequest The federated user details containing username and other required information
     * @return UserDetailsResponse containing the created user's details
     * @throws OAuth2AuthenticationException if there is an error during user creation
     */
    public UserDetailsResponse createFedratedUser(FederatedUserDto userRequest) {
        LOGGER.info("Creating federated user with username: {}", userRequest.getUserName());

        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();

            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_CREATE_FEDRATED_USER);

            UserDetailsResponse userDetailsResponse = currentWebClient.method(HttpMethod.POST).uri(uri)
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .contentType(MediaType.APPLICATION_JSON).bodyValue(userRequest).retrieve()
                    .bodyToMono(UserDetailsResponse.class).block();
            LOGGER.info("Successfully created federated user: {}", userRequest.getUserName());
            return objectMapper.convertValue(userDetailsResponse, new TypeReference<UserDetailsResponse>() {
            });
        } catch (WebClientResponseException ex) {
            LOGGER.error("Failed to create federated user: {}", userRequest.getUserName(), ex);
            handleWebClientResponseException(ex, userRequest);
        } catch (Exception ex) {
            LOGGER.error("Unexpected error while creating federated user: {}", userRequest.getUserName(), ex);
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, UNEXPECTED_ERROR, null);
            throw new OAuth2AuthenticationException(error);
        }
        return null;
    }
}
