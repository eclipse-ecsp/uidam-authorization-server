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
import org.eclipse.ecsp.oauth2.server.core.common.constants.ResponseMessages;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.PasswordRecoveryException;
import org.eclipse.ecsp.oauth2.server.core.exception.UidamApplicationException;
import org.eclipse.ecsp.oauth2.server.core.exception.UserNotFoundException;
import org.eclipse.ecsp.oauth2.server.core.interceptor.ClientAddCorrelationIdInterceptor;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.metrics.MetricType;
import org.eclipse.ecsp.oauth2.server.core.request.dto.BaseUserDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.FederatedUserDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.UserEvent;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.response.UserErrorResponse;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodeVerifyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaBackupCodesResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaEnrollInitiateResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.MfaStatusResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.PasswordPolicyResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.UserEventResponse;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.service.impl.CaptchaServiceImpl;
import org.eclipse.ecsp.oauth2.server.core.utils.MfaSecretEncryptionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.INVALID_INPUT_ERROR;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.INVALID_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_ADD_USER_EVENTS_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_CREATE_FEDRATED_USER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_BACKUP_CODES_GENERATE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_BACKUP_CODES_VERIFY;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_ENROLL_ACTIVATE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_ENROLL_INITIATE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_RECOVERY_SEND;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_RECOVERY_VERIFY;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_REVOKE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_SECRET;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_MFA_STATUS;
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
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.TENANT_ID_HEADER;
import static org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils.obtainRecaptchaResponse;
import static org.eclipse.ecsp.oauth2.server.core.utils.RequestResponseLogger.logRequest;
import static org.eclipse.ecsp.oauth2.server.core.utils.RequestResponseLogger.logResponse;

/**
 * The UserManagementClient class manages connections with the User Management Service. It uses a WebClient to make HTTP
 * requests and an ObjectMapper to serialize and deserialize JSON.
 */
@Component
public class UserManagementClient {

    private static final String BACKUP_CODE = "backupCode";

    private static final String RECOVERY_KEY = "recoveryKey";

    private static final Logger LOGGER = LoggerFactory.getLogger(UserManagementClient.class);

    private ObjectMapper objectMapper = new ObjectMapper();

    private final TenantConfigurationService tenantConfigurationService;
    private final CaptchaServiceImpl captchaServiceImpl;
    private final WebClient webClient;
    private final AuthorizationMetricsService metricsService;

    /**
     * Constructor for UserManagementClient. It initializes the tenant configuration service for dynamic tenant
     * resolution.
     *
     * @param tenantConfigurationService the service to retrieve tenant properties from
     * @param captchaServiceImpl the captcha service implementation
     */
    @Autowired
    public UserManagementClient(TenantConfigurationService tenantConfigurationService,
            CaptchaServiceImpl captchaServiceImpl,
            AuthorizationMetricsService metricsService) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.captchaServiceImpl = captchaServiceImpl;
        this.metricsService = metricsService;
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
            CaptchaServiceImpl captchaServiceImpl, WebClient webClient,
            AuthorizationMetricsService metricsService) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.captchaServiceImpl = captchaServiceImpl;
        this.webClient = webClient;
        this.metricsService = metricsService;
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
                    .header(ACCOUNT_NAME_HEADER, accountName)
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .accept(MediaType.APPLICATION_JSON).retrieve()
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
            TenantProperties tenantProperties = getCurrentTenantProperties();
            String tenantId = tenantProperties.getTenantId();
            OAuth2Error error = handleUserFetchError(ex.getStatusCode(), userErrorResponse, tenantId);
            metricsService.incrementMetricsForTenant(tenantId, MetricType.FAILURE_LOGIN_ATTEMPTS);
            throw new OAuth2AuthenticationException(error);
        } catch (Exception ex) {
            LOGGER.error("error while fetching user details for username {} from user-mgmt, ex: {}", username, ex);
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "Unable to validate username", null);
            TenantProperties tenantProperties = getCurrentTenantProperties();
            String tenantId = tenantProperties.getTenantId();
            metricsService.incrementMetricsForTenant(tenantId, MetricType.FAILURE_LOGIN_ATTEMPTS);
            throw new OAuth2AuthenticationException(error);
        }
    }

    /**
     * This method adds a user event to the User Management Service. It makes a POST request to the User Management
     * Service to add the user event. If an error occurs during the process, it throws an OAuth2AuthenticationException.
     *
     * @param userEvent the user event to be added
     * @param userId the ID of the user for whom the event is to be added
     * @return UserEventResponse containing user status and lock duration information
     */
    public UserEventResponse addUserEvent(UserEvent userEvent, String userId) {
        LOGGER.debug("Adding user event {} details for userId {} to user-mgmt", userEvent.getType(), userId);

        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();

            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_ADD_USER_EVENTS_ENDPOINT);
            UserEventResponse response;

            response = currentWebClient.method(HttpMethod.POST).uri(uri, userId)
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .contentType(MediaType.APPLICATION_JSON).bodyValue(userEvent).retrieve()
                    .bodyToMono(UserEventResponse.class)
                    .block();
            
            LOGGER.info("User event processed for userId {}: status={}, lockDurationMinutes={}", 
                userId, response.getUserStatus(), response.getLockDurationMinutes());
            
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
                    .header(ACCOUNT_NAME_HEADER, accountName)
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .contentType(MediaType.APPLICATION_JSON).retrieve()
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
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
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
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
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
        LOGGER.debug("## validateCaptchaAndAddRequiredParameters - END");
        return userDto;
    }

    private String extractMessage(String input) {
        if (!StringUtils.hasText(input)) {
            return null;
        }

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
            } else if (HttpStatus.CONFLICT == ex.getStatusCode()) {
                errorCode = CustomOauth2TokenGenErrorCodes.RECORD_ALREADY_EXISTS.name();
                errorDesc = USER_ALREADY_EXISTS_PLEASE_TRY_AGAIN;
            } else if (HttpStatus.BAD_REQUEST == ex.getStatusCode()) {
                errorCode = CustomOauth2TokenGenErrorCodes.BAD_REQUEST.name();
                String extractedMessage = this.extractMessage(userErrorResponse.getMessage());
                if (StringUtils.hasText(extractedMessage)
                        && extractedMessage.contains(PASSWORD)) {
                    errorDesc = INVALID_PASSWORD;
                } else if (StringUtils.hasText(extractedMessage)) {
                    errorDesc = INVALID_INPUT_ERROR;
                } else {
                    // extractMessage returned null, use UNEXPECTED_ERROR
                    errorDesc = UNEXPECTED_ERROR;
                }
            } else {
                errorCode = OAuth2ErrorCodes.SERVER_ERROR;
            }
        } else {
            // Cannot parse response body, treat as server error even if BAD_REQUEST status
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

            password = currentWebClient.method(HttpMethod.GET).uri(uri)
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .accept(MediaType.APPLICATION_JSON).retrieve()
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
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
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

    // ─────────────────────────────────────────────────────────────────────────
    //  MFA REST methods (internal auth-server → user-management, no gateway JWT)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Initiate MFA enrollment for a user: generates a secret in user-management and returns it.
     *
     * @param username the user's username
     * @return {@link MfaEnrollInitiateResponseDto} with secret, QR URI and manual key
     */
    public MfaEnrollInitiateResponseDto initiateMfaEnrollment(String username) {
        LOGGER.info("[MFA] Initiating enrollment for username='{}' via user-mgmt", username);
        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();
            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_MFA_ENROLL_INITIATE);
            return currentWebClient.method(HttpMethod.POST).uri(uri, username)
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .contentType(MediaType.APPLICATION_JSON).retrieve()
                    .bodyToMono(MfaEnrollInitiateResponseDto.class).block();
        } catch (Exception ex) {
            LOGGER.error("[MFA] Error initiating enrollment for username='{}': ", username, ex);
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "Failed to initiate MFA enrollment", null));
        }
    }

    /**
     * Activate MFA enrollment in user-management (mark PENDING → ACTIVE).
     *
     * @param username the user's username
     */
    public void activateMfaEnrollment(String username) {
        LOGGER.info("[MFA] Activating enrollment for username='{}' via user-mgmt", username);
        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();
            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_MFA_ENROLL_ACTIVATE);
            currentWebClient.method(HttpMethod.POST).uri(uri, username)
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .contentType(MediaType.APPLICATION_JSON).retrieve()
                    .toBodilessEntity().block();
        } catch (Exception ex) {
            LOGGER.error("[MFA] Error activating enrollment for username='{}': ", username, ex);
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "Failed to activate MFA enrollment", null));
        }
    }

    /**
     * Get MFA enrollment status for a user.
     *
     * @param username the user's username
     * @return Optional of {@link MfaStatusResponseDto}, empty on 404 or error
     */
    public java.util.Optional<MfaStatusResponseDto> getMfaStatus(String username) {
        LOGGER.debug("[MFA] Fetching MFA status for username='{}'", username);
        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();
            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_MFA_STATUS);
            MfaStatusResponseDto response = currentWebClient.method(HttpMethod.GET).uri(uri, username)
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .accept(MediaType.APPLICATION_JSON).retrieve()
                    .bodyToMono(MfaStatusResponseDto.class).block();
            return java.util.Optional.ofNullable(response);
        } catch (WebClientResponseException ex) {
            if (ex.getStatusCode().isSameCodeAs(HttpStatus.NOT_FOUND)) {
                return java.util.Optional.empty();
            }
            LOGGER.error("[MFA] Error fetching MFA status for username='{}': ", username, ex);
            return java.util.Optional.empty();
        } catch (Exception ex) {
            LOGGER.error("[MFA] Unexpected error fetching MFA status for username='{}': ", username, ex);
            return java.util.Optional.empty();
        }
    }

    /**
     * Get the TOTP secret for a user (ACTIVE or PENDING enrollment only).
     *
     * <p>The secret is stored encrypted in user-management (AES-256-GCM). This method
     * fetches the encrypted blob and decrypts it using the tenant's configured
     * {@code mfa-secret-encryption-key} and {@code mfa-secret-encryption-salt} before returning.
     *
     * @param username the user's username
     * @return Optional containing the decrypted Base32 TOTP secret, or empty if not found
     */
    public java.util.Optional<String> getMfaSecret(String username) {
        LOGGER.debug("[MFA] Fetching TOTP secret for username='{}'", username);
        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();
            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_MFA_SECRET);
            String encryptedSecret = currentWebClient.method(HttpMethod.GET).uri(uri, username)
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .accept(MediaType.TEXT_PLAIN).retrieve()
                    .bodyToMono(String.class).block();
            // Defensive: strip surrounding JSON quotes if the server returned a quoted string.
            if (encryptedSecret != null && encryptedSecret.startsWith("\"")
                    && encryptedSecret.endsWith("\"") && encryptedSecret.length() > 1) {
                encryptedSecret = encryptedSecret.substring(1, encryptedSecret.length() - 1);
            }
            if (encryptedSecret == null) {
                return java.util.Optional.empty();
            }
            // Decrypt the secret using the per-tenant key/salt before returning.
            String plainSecret = decryptMfaSecret(encryptedSecret, tenantProperties);
            return java.util.Optional.of(plainSecret);
        } catch (WebClientResponseException ex) {
            if (ex.getStatusCode().isSameCodeAs(HttpStatus.NOT_FOUND)) {
                LOGGER.error("[MFA] Error fetching secret for username='{}'", username, ex);
            } else {
                LOGGER.error("[MFA] Unexpected error fetching secret for username='{}': {}", username, ex.getMessage());
            }
            return java.util.Optional.empty();
        }
    }

    /**
     * Decrypt the encrypted MFA secret using the tenant-configured key and salt.
     *
     * @param encryptedSecret the AES-256-GCM encrypted, Base64-encoded TOTP secret
     * @param tenantProperties the properties for the current tenant
     * @return the decrypted Base32 TOTP secret
     */
    private String decryptMfaSecret(String encryptedSecret, TenantProperties tenantProperties) {
        String key  = resolveEncryptionKey(tenantProperties);
        String salt = resolveEncryptionSalt(tenantProperties);
        try {
            return MfaSecretEncryptionUtil.decrypt(encryptedSecret, key, salt);
        } catch (MfaSecretEncryptionUtil.MfaDecryptionException ex) {
            LOGGER.error("[MFA] Failed to decrypt TOTP secret for tenant='{}': {}",
                    tenantProperties.getTenantId(), ex.getMessage());
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "Failed to decrypt MFA secret", null));
        }
    }

    private String resolveEncryptionKey(TenantProperties props) {
        if (props.getMfaSecretEncryptionKey() != null && !props.getMfaSecretEncryptionKey().isBlank()) {
            return props.getMfaSecretEncryptionKey();
        }
        return "ChangeMe-MfaKey!";
    }

    private String resolveEncryptionSalt(TenantProperties props) {
        if (props.getMfaSecretEncryptionSalt() != null && !props.getMfaSecretEncryptionSalt().isBlank()) {
            return props.getMfaSecretEncryptionSalt();
        }
        return "ChangeMe-MfaSalt";
    }

    /**
     * Revoke MFA enrollment for a user (triggers re-enrollment on next login).
     *
     * @param username the user's username
     */
    public void revokeMfaEnrollment(String username) {
        LOGGER.info("[MFA] Revoking enrollment for username='{}' via user-mgmt", username);
        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();
            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_MFA_REVOKE);
            currentWebClient.method(HttpMethod.DELETE).uri(uri, username)
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .retrieve().toBodilessEntity().block();
        } catch (Exception ex) {
            LOGGER.error("[MFA] Error revoking enrollment for username='{}'", username, ex);
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "Failed to revoke MFA enrollment", null));
        }
    }

    /**
     * Send a one-time recovery key to the user's registered email address via user-management.
     *
     * @param username the user's username
     */
    public void sendMfaRecoveryKey(String username) {
        LOGGER.info("[MFA] Sending recovery key for username='{}' via user-mgmt", username);
        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();
            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_MFA_RECOVERY_SEND);
            currentWebClient.method(HttpMethod.POST).uri(uri, username)
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .contentType(MediaType.APPLICATION_JSON).retrieve()
                    .onStatus(HttpStatusCode::isError, clientResponse -> {
                        LOGGER.error("[MFA] User-management returned status {} for recovery key send, user='{}'",
                                clientResponse.statusCode(), username);
                        return clientResponse.bodyToMono(String.class)
                                .defaultIfEmpty("Unknown error from user-management")
                                .flatMap(body -> {
                                    LOGGER.error("[MFA] User-management error body: {}", body);
                                    return reactor.core.publisher.Mono.error(new OAuth2AuthenticationException(
                                            new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                                                    "Failed to send MFA recovery email: " + body, null)));
                                });
                    })
                    .toBodilessEntity().block();
        } catch (OAuth2AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            LOGGER.error("[MFA] Error sending recovery key for username='{}': {}", username, ex.getMessage());
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "Failed to send MFA recovery key: " + ex.getMessage(), null));
        }
    }

    /**
     * Verify the user's recovery key and revoke enrollment if valid.
     *
     * @param username    the user's username
     * @param recoveryKey the 6-character key entered by the user
     * @return {@code true} if the key is valid and enrollment was revoked
     */
    public boolean verifyMfaRecoveryKey(String username, String recoveryKey) {
        LOGGER.info("[MFA] Verifying recovery key for username='{}' via user-mgmt", username);
        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();
            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_MFA_RECOVERY_VERIFY);
            Map<String, String> body = Map.of(RECOVERY_KEY, recoveryKey);
            Boolean result = currentWebClient.method(HttpMethod.POST)
                    .uri(uri.replace("{username}", username))
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(Boolean.class).block();
            return Boolean.TRUE.equals(result);
        } catch (Exception ex) {
            LOGGER.error("[MFA] Error verifying recovery key for username='{}': {}", username, ex.getMessage());
            return false;
        }
    }

    /**
     * Generate (or regenerate) a set of MFA backup codes for a user via user-management.
     *
     * @param username the user's username
     * @return {@link MfaBackupCodesResponseDto} with the freshly generated plain-text codes
     */
    public MfaBackupCodesResponseDto generateMfaBackupCodes(String username) {
        LOGGER.info("[MFA] Generating backup codes for username='{}' via user-mgmt", username);
        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();
            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_MFA_BACKUP_CODES_GENERATE);
            return currentWebClient.method(HttpMethod.POST).uri(uri, username)
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .contentType(MediaType.APPLICATION_JSON).retrieve()
                    .bodyToMono(MfaBackupCodesResponseDto.class).block();
        } catch (Exception ex) {
            LOGGER.error("[MFA] Error generating backup codes for username='{}': {}", username, ex.getMessage());
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "Failed to generate MFA backup codes", null));
        }
    }

    /**
     * Verify a single MFA backup code for a user via user-management. On success the code is
     * consumed (single-use) in user-management.
     *
     * @param username   the user's username
     * @param backupCode the plain-text backup code entered by the user
     * @return {@link MfaBackupCodeVerifyResponseDto} with validity and remaining-code count;
     *         an invalid result is returned on any error
     */
    public MfaBackupCodeVerifyResponseDto verifyMfaBackupCode(String username, String backupCode) {
        LOGGER.info("[MFA] Verifying backup code for username='{}' via user-mgmt", username);
        try {
            TenantProperties tenantProperties = getCurrentTenantProperties();
            WebClient currentWebClient = getWebClientForCurrentTenant();
            String uri = tenantProperties.getExternalUrls().get(TENANT_EXTERNAL_URLS_MFA_BACKUP_CODES_VERIFY);
            Map<String, String> body = Map.of(BACKUP_CODE, backupCode);
            return currentWebClient.method(HttpMethod.POST)
                    .uri(uri.replace("{username}", username))
                    .header(IgniteOauth2CoreConstants.CORRELATION_ID, UUID.randomUUID().toString())
                    .header(TENANT_ID_HEADER, tenantProperties.getTenantId())
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(MfaBackupCodeVerifyResponseDto.class).block();
        } catch (Exception ex) {
            LOGGER.error("[MFA] Error verifying backup code for username='{}': {}", username, ex.getMessage());
            return new MfaBackupCodeVerifyResponseDto(false, 0, false);
        }
    }

    /**
     * Handles user fetch errors and creates appropriate OAuth2Error with metrics tracking.
     * Enhanced to support temporary lock information from the user management service.
     *
     * @param statusCode the HTTP status code from the error response
     * @param userErrorResponse the error response from the user management service (can be null)
     * @param tenantId the tenant ID for metrics tracking
     * @return OAuth2Error with appropriate error code and description, including temporary lock info if applicable
     */
    private OAuth2Error handleUserFetchError(HttpStatusCode statusCode, UserErrorResponse userErrorResponse, 
                                            String tenantId) {
        String errorCode;
        String errorDesc;
        String errorMessage = userErrorResponse != null ? userErrorResponse.getMessage() : null;

        if (errorMessage != null) {
            if (HttpStatus.NOT_FOUND.isSameCodeAs(statusCode)) {
                errorCode = CustomOauth2TokenGenErrorCodes.USER_NOT_FOUND.name();
                // Used generic error message to prevent username enumeration attacks
                errorDesc = ResponseMessages.INVALID_CREDENTIALS_ERROR;
                metricsService.incrementMetricsForTenant(tenantId, MetricType.FAILURE_LOGIN_USER_NOT_FOUND);
            } else if (HttpStatus.FORBIDDEN.isSameCodeAs(statusCode)) {
                // IMPORTANT: Check for temporary lock FIRST before checking message content
                // because temporary lock messages contain "account" which would match the wrong condition
                if (Boolean.TRUE.equals(userErrorResponse.getIsTemporaryLock()) 
                        && userErrorResponse.getMinutesLeftToUnlock() != null) {
                    errorCode = "USER_TEMPORARILY_BLOCKED";
                    // Use the detailed message from user-management service which includes minutes
                    errorDesc = errorMessage;
                    metricsService.incrementMetricsForTenant(tenantId, MetricType.FAILURE_LOGIN_USER_BLOCKED);
                } else if (errorMessage.toLowerCase().contains("account")) {
                    // Check if it's account not found
                    errorCode = CustomOauth2TokenGenErrorCodes.ACCOUNT_NOT_FOUND.name();
                    errorDesc = CustomOauth2TokenGenErrorCodes.ACCOUNT_NOT_FOUND.getDescription();
                } else {
                    // Generic user not active
                    errorCode = CustomOauth2TokenGenErrorCodes.USER_NOT_ACTIVE.name();
                    errorDesc = CustomOauth2TokenGenErrorCodes.USER_NOT_ACTIVE.getDescription();
                    metricsService.incrementMetricsForTenant(tenantId, MetricType.FAILURE_LOGIN_USER_BLOCKED);
                }
            } else {
                errorCode = OAuth2ErrorCodes.SERVER_ERROR;
                errorDesc = errorMessage;
            }
        } else {
            errorCode = OAuth2ErrorCodes.SERVER_ERROR;
            errorDesc = "Unable to validate username";
        }

        return new OAuth2Error(errorCode, errorDesc, null);
    }
}
