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
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.interceptor.ClientAddCorrelationIdInterceptor;
import org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_CLIENT_BY_CLIENT_ID_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_MANAGEMENT_ENV;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.UIDAM;
import static org.eclipse.ecsp.oauth2.server.core.utils.RequestResponseLogger.logRequest;
import static org.eclipse.ecsp.oauth2.server.core.utils.RequestResponseLogger.logResponse;

/**
 * The AuthManagementClient class manages connections with the Auth Management Service.
 * It uses a WebClient to make HTTP requests and an ObjectMapper to serialize and deserialize JSON.
 */
@Component
public class AuthManagementClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthManagementClient.class);

    private WebClient webClient;

    private ObjectMapper objectMapper = new ObjectMapper();

    private TenantProperties tenantProperties;

    /**
     * Constructor for AuthManagementClient.
     * It initializes tenantProperties using the provided TenantConfigurationService.
     * It also builds the WebClient with the base URL from tenantProperties.
     *
     * @param tenantConfigurationService the service to fetch tenant properties.
     */
    @Autowired
    public AuthManagementClient(TenantConfigurationService tenantConfigurationService) {
        tenantProperties = tenantConfigurationService.getTenantProperties(UIDAM);
        this.webClient = WebClient.builder().baseUrl(tenantProperties.getExternalUrls()
          .get(TENANT_EXTERNAL_URLS_USER_MANAGEMENT_ENV))
                .filter(ClientAddCorrelationIdInterceptor.addCorrelationIdAndContentType())
                .filter(logRequest()).filter(logResponse())
          .build();

    }

    /**
     * This method is called after the constructor.
     * It configures the ObjectMapper to include non-null properties and not fail on unknown properties.
     */
    @PostConstruct
    private void init() {
        objectMapper.setSerializationInclusion(Include.NON_NULL)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    }

    /**
     * This method fetches the client details from the Auth Management Service.
     * It makes a GET request to the Auth Management Service and retrieves the client details.
     * If the HTTP status is OK, it converts the response data to a RegisteredClientDetails object and returns it.
     * If an error occurs during the process, it returns null.
     *
     * @param clientId the ID of the client.
     * @return the client details as a RegisteredClientDetails object, or null if an error occurs.
     */
    public RegisteredClientDetails getClientDetails(String clientId) {
        LOGGER.info("fetching client details for clientId {} from auth-mgmt", clientId);
        String uri = tenantProperties.getExternalUrls().get(
                TENANT_EXTERNAL_URLS_CLIENT_BY_CLIENT_ID_ENDPOINT);
        try {
            RegisteredClientDetails response = webClient.get()
                .uri(uri, clientId)
                .accept(MediaType.APPLICATION_JSON).retrieve()
                .bodyToMono(RegisteredClientDetails.class).block();

            if (response != null && HttpStatus.OK.equals(response.getHttpStatus())) {

                return objectMapper.convertValue(response.getData(), new TypeReference<RegisteredClientDetails>() {
                });
            }
            return response;

        } catch (Exception ex) {
            LOGGER.error("error while fetching client details for clientId {} from auth-mgmt, ex: {}", clientId, ex);
        }
        return null;

    }

}
