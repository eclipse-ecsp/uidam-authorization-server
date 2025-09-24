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

import org.eclipse.ecsp.oauth2.server.core.request.dto.RevokeTokenRequest;
import org.eclipse.ecsp.oauth2.server.core.response.BaseResponse;
import org.eclipse.ecsp.oauth2.server.core.service.AuthorizationService;
import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The AuthorizationController class is a REST controller that manages the token revocation process for the OAuth2
 * server.
 * It exposes the /revoke/revokeByAdmin endpoint for this purpose.
 */
@RestController
@RequestMapping({"/{tenantId}/revoke/revokeByAdmin", "/revoke/revokeByAdmin"})
public class AuthorizationController {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationController.class);
    @Autowired
    AuthorizationService authorizationService;


    /**
     * This API endpoint is used to revoke any active token of a given client.
     * It takes in an authorization token and a request body containing the clientId or username.
     * It calls the revokeToken method of the IgniteOauth2AuthorizationService.
     * It then builds a response and returns it.
     *
     * @param tenantId The tenant ID.
     * @param authorization The authorization token.
     * @param revokeTokenRequest The request body containing the clientId or username.
     * @return A ResponseEntity object containing a BaseResponse with the response message.
     */
    @PostMapping(consumes = { MediaType.APPLICATION_FORM_URLENCODED_VALUE })
    public ResponseEntity<BaseResponse> revokeToken(@PathVariable(value = "tenantId", required = false) String tenantId,
                                                   @RequestHeader(value = "Authorization",
        required = true) String authorization, RevokeTokenRequest revokeTokenRequest) {
        tenantId = TenantUtils.resolveTenantId(tenantId);
        LOGGER.info("Revoke token request for clientId: {} or username: {} for tenantId: {}",
                revokeTokenRequest.getClientId(), revokeTokenRequest.getUsername(), tenantId);
        String response = authorizationService.revokeToken(revokeTokenRequest, authorization);
        return buildResponse(response, null, HttpStatus.OK, null);
    }

    /**
     * This method is used to build the response for the authorization APIs.
     * It creates a BaseResponse object with the provided message, data, status code, and code.
     * It then wraps this BaseResponse object in a ResponseEntity and returns it.
     *
     * @param message The message for the response.
     * @param data The data for the response.
     * @param statuscode The status code for the response.
     * @param code The code for the response.
     * @return A ResponseEntity object containing the BaseResponse.
     */
    private ResponseEntity<BaseResponse> buildResponse(String message, Object data,
                                                       HttpStatus statuscode, String code) {
        BaseResponse response = new BaseResponse(code, message, data, statuscode);
        return new ResponseEntity<>(response, statuscode);
    }
}
