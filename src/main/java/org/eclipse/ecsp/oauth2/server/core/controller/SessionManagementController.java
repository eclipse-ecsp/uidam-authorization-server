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

package org.eclipse.ecsp.oauth2.server.core.controller;

import jakarta.validation.Valid;
import org.eclipse.ecsp.oauth2.server.core.request.dto.AdminGetActiveSessionsRequestDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.AdminInvalidateSessionsRequestDto;
import org.eclipse.ecsp.oauth2.server.core.request.dto.InvalidateSessionsRequestDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.ActiveSessionsResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.ApiResponse;
import org.eclipse.ecsp.oauth2.server.core.response.dto.InvalidateSessionsResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.SessionManagementService;
import org.eclipse.ecsp.oauth2.server.core.utils.JwtTokenValidator;
import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.BEARER;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MANAGE_USERS_SCOPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.SELF_MANAGE_SCOPE;

/**
 * REST controller for managing active sessions (tokens).
 * Provides endpoints for both self-service and admin operations.
 */
@RestController
@RequestMapping({"/{tenantId}", ""})
public class SessionManagementController {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(SessionManagementController.class);
    private static final int BEGIN_INDEX = 7;
    private static final String INVALID_OR_INSUFFICIENT_PERMISSIONS = "Invalid or insufficient permissions";
    private static final String INVALID_TOKEN = "INVALID_TOKEN";
    private static final String INTERNAL_ERROR = "INTERNAL_ERROR";
    
    private final SessionManagementService sessionManagementService;
    private final JwtTokenValidator jwtTokenValidator;
    
    /**
     * Constructor for SessionManagementController.
     *
     * @param sessionManagementService the session management service
     * @param jwtTokenValidator the JWT token validator
     */
    public SessionManagementController(SessionManagementService sessionManagementService,
                                      JwtTokenValidator jwtTokenValidator) {
        this.sessionManagementService = sessionManagementService;
        this.jwtTokenValidator = jwtTokenValidator;
    }
    
    /**
     * Fetches active tokens for the authenticated user (self-service).
     * Required scope: SelfManage
     *
     * @param tenantId the tenant ID
     * @param authorization the authorization header containing the Bearer token
     * @return response containing active sessions
     */
    @GetMapping("/self/tokens/active")
    public ResponseEntity<ApiResponse<ActiveSessionsResponseDto>> getSelfActiveSessions(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            @RequestHeader(value = "Authorization", required = true) String authorization) {
        
        tenantId = TenantUtils.resolveTenantId(tenantId);
        
        // Validate token with required scope
        if (!isValidToken(authorization, SELF_MANAGE_SCOPE)) {
            LOGGER.error("Token validation failed for getSelfActiveSessions");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(INVALID_TOKEN, INVALID_OR_INSUFFICIENT_PERMISSIONS));
        }
        
        // Extract username and token from Bearer token
        String token = authorization.substring(BEGIN_INDEX);
        String username = jwtTokenValidator.getClaimsFromToken(token).get("username", String.class);
        
        LOGGER.info("Fetching active sessions for authenticated user");
        
        try {
            ActiveSessionsResponseDto response = sessionManagementService.getActiveSessionsForUser(
                    username, token, tenantId);
            return ResponseEntity.ok(ApiResponse.success(response));
        } catch (Exception e) {
            LOGGER.error("Error fetching active sessions: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error(INTERNAL_ERROR, 
                            "An error occurred while fetching tokens"));
        }
    }
    
    /**
     * Invalidates one or more active tokens for the authenticated user (self-service).
     * Required scope: SelfManage
     *
     * @param tenantId the tenant ID
     * @param authorization the authorization header containing the Bearer token
     * @param request the invalidate sessions request
     * @return response containing invalidation results
     */
    @PostMapping("/self/tokens/invalidate")
    public ResponseEntity<ApiResponse<InvalidateSessionsResponseDto>> invalidateSelfSessions(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            @RequestHeader(value = "Authorization", required = true) String authorization,
            @Valid @RequestBody InvalidateSessionsRequestDto request) {
        
        tenantId = TenantUtils.resolveTenantId(tenantId);
        
        // Validate token with required scope
        if (!isValidToken(authorization, SELF_MANAGE_SCOPE)) {
            LOGGER.error("Token validation failed for invalidateSelfSessions");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(INVALID_TOKEN, INVALID_OR_INSUFFICIENT_PERMISSIONS));
        }
        
        // Extract username from Bearer token
        String token = authorization.substring(BEGIN_INDEX);
        String username = jwtTokenValidator.getClaimsFromToken(token).get("username", String.class);
        
        LOGGER.info("Invalidating sessions for authenticated user");
        
        try {
            InvalidateSessionsResponseDto response = sessionManagementService.invalidateSessionsForUser(
                    username, request.getTokenIds(), tenantId);
            
            if (response.getFailedSessions() != null && !response.getFailedSessions().isEmpty() 
                    && response.getInvalidatedSessions() > 0) {
                return ResponseEntity.status(HttpStatus.MULTI_STATUS)
                        .body(ApiResponse.partialSuccess(response));
            }
            
            return ResponseEntity.ok(ApiResponse.success(response));
        } catch (Exception e) {
            LOGGER.error("Error invalidating sessions: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error(INTERNAL_ERROR, 
                            "An error occurred while invalidating tokens"));
        }
    }
    
    /**
     * Fetches active tokens for a specific user (admin operation).
     * Required scope: ManageUsers
     *
     * @param tenantId the tenant ID
     * @param authorization the authorization header containing the Bearer token
     * @param request the request containing username
     * @return response containing active sessions
     */
    @PostMapping("/admin/tokens/active")
    public ResponseEntity<ApiResponse<ActiveSessionsResponseDto>> getAdminActiveSessions(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            @RequestHeader(value = "Authorization", required = true) String authorization,
            @Valid @RequestBody AdminGetActiveSessionsRequestDto request) {
        
        tenantId = TenantUtils.resolveTenantId(tenantId);
        
        // Validate token with required scope
        if (!isValidToken(authorization, MANAGE_USERS_SCOPE)) {
            LOGGER.error("Token validation failed for getAdminActiveSessions");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(INVALID_TOKEN, INVALID_OR_INSUFFICIENT_PERMISSIONS));
        }
        
        String username = request.getUsername();
        
        LOGGER.info("Admin fetching active sessions for target user");
        
        try {
            ActiveSessionsResponseDto response = sessionManagementService.getActiveSessionsForUser(
                    username, null, tenantId);
            return ResponseEntity.ok(ApiResponse.success(response));
        } catch (Exception e) {
            LOGGER.error("Error fetching active sessions: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error(INTERNAL_ERROR, 
                            "An error occurred while fetching tokens"));
        }
    }
    
    /**
     * Invalidates one or more active tokens for a specific user (admin operation).
     * Required scope: ManageUsers
     *
     * @param tenantId the tenant ID
     * @param authorization the authorization header containing the Bearer token
     * @param request the admin invalidate sessions request
     * @return response containing invalidation results
     */
    @PostMapping("/admin/tokens/invalidate")
    public ResponseEntity<ApiResponse<InvalidateSessionsResponseDto>> invalidateAdminSessions(
            @PathVariable(value = "tenantId", required = false) String tenantId,
            @RequestHeader(value = "Authorization", required = true) String authorization,
            @Valid @RequestBody AdminInvalidateSessionsRequestDto request) {
        
        tenantId = TenantUtils.resolveTenantId(tenantId);
        
        // Validate token with required scope
        if (!isValidToken(authorization, MANAGE_USERS_SCOPE)) {
            LOGGER.error("Token validation failed for invalidateAdminSessions");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(INVALID_TOKEN, INVALID_OR_INSUFFICIENT_PERMISSIONS));
        }
        
        String username = request.getUsername();
        
        LOGGER.info("Admin invalidating sessions for target user");
        
        try {
            InvalidateSessionsResponseDto response = sessionManagementService.invalidateSessionsForUser(
                    username, request.getTokenIds(), tenantId);
            response.setUsername(username);
            
            if (response.getFailedSessions() != null && !response.getFailedSessions().isEmpty() 
                    && response.getInvalidatedSessions() > 0) {
                return ResponseEntity.status(HttpStatus.MULTI_STATUS)
                        .body(ApiResponse.partialSuccess(response));
            }
            
            return ResponseEntity.ok(ApiResponse.success(response));
        } catch (Exception e) {
            LOGGER.error("Error invalidating sessions: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error(INTERNAL_ERROR, 
                            "An error occurred while invalidating tokens"));
        }
    }
    
    /**
     * Validates the JWT token by checking if it contains the Bearer prefix, required scope,
     * and performs database introspection to ensure the token is still active and not revoked.
     * This provides OAuth2-like token introspection by validating against the authorization table.
     *
     * @param token the authorization header value
     * @param requiredScope the scope that must be present in the token
     * @return true if the token is valid, contains the required scope, and is active in database
     */
    private boolean isValidToken(String token, String requiredScope) {
        LOGGER.debug("Validating token with required scope and database introspection: {}", requiredScope);
        if (token != null && token.startsWith(BEARER + " ")) {
            // Use introspectToken instead of validateToken for database-backed validation
            return jwtTokenValidator.introspectToken(token.substring(BEGIN_INDEX), requiredScope);
        }
        return false;
    }
}
