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

package org.eclipse.ecsp.oauth2.server.core.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientService;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.entities.Authorization;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationRepository;
import org.eclipse.ecsp.oauth2.server.core.response.dto.ActiveSessionDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.ActiveSessionsResponseDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.FailedSessionDto;
import org.eclipse.ecsp.oauth2.server.core.response.dto.InvalidateSessionsResponseDto;
import org.eclipse.ecsp.oauth2.server.core.service.SessionManagementService;
import org.eclipse.ecsp.oauth2.server.core.utils.JwtTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Implementation of SessionManagementService for managing active sessions.
 */
@Service
public class SessionManagementServiceImpl implements SessionManagementService {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(SessionManagementServiceImpl.class);
    private static final String AUTHORIZATION_CODE = "authorization_code";
    private static final String DEVICE_INFO_KEY = "java.security.Principal";
    private static final String INVALIDATED_KEY = "invalidated";
    private static final String INVALIDATION_REASON_KEY = "invalidationReason";
    
    // Device and browser name constants
    private static final String UNKNOWN_DEVICE = "Unknown Device";
    private static final String INSOMNIA = "Insomnia";
    private static final String HTTPIE = "HTTPie";
    private static final String OPERA = "Opera";
    
    private final AuthorizationRepository authorizationRepository;
    private final CacheClientService cacheClientService;
    private final ObjectMapper objectMapper;
    private final JwtTokenValidator jwtTokenValidator;
    
    /**
     * Constructor for SessionManagementServiceImpl.
     *
     * @param authorizationRepository the authorization repository
     * @param cacheClientService the cache client service
     * @param objectMapper the object mapper
     * @param jwtTokenValidator the JWT token validator
     */
    public SessionManagementServiceImpl(
            AuthorizationRepository authorizationRepository,
            CacheClientService cacheClientService,
            ObjectMapper objectMapper,
            JwtTokenValidator jwtTokenValidator) {
        this.authorizationRepository = authorizationRepository;
        this.cacheClientService = cacheClientService;
        this.objectMapper = objectMapper;
        this.jwtTokenValidator = jwtTokenValidator;
    }
    
    @Override
    @Transactional(readOnly = true)
    public ActiveSessionsResponseDto getActiveSessionsForUser(
            String username, String currentTokenString, String tenantId) {
        LOGGER.info("Fetching active sessions for user");
        
        // Phase 1: Fetch from database using optimized indexed query
        // This query filters at the database level by principal_name, grant_type, and expiry time
        List<Authorization> authorizations = authorizationRepository
                .findActiveSessionsByPrincipalNameAndGrantType(
                        username, AUTHORIZATION_CODE, Instant.now());
        
        LOGGER.debug("Retrieved {} authorization records from database", 
                authorizations.size());
        
        // Phase 2: Programmatic filtering - filter out invalidated tokens
        List<Authorization> activeAuthorizations = authorizations.stream()
                .filter(this::isNotInvalidated)
                .collect(Collectors.toList());
        
        // Phase 3: Populate client names and build DTOs
        List<ActiveSessionDto> sessions = new ArrayList<>();
        
        for (Authorization auth : activeAuthorizations) {
            String clientName = getClientName(auth.getRegisteredClientId(), tenantId);
            String deviceInfo = parseDeviceInfo(auth.getAttributes());
            Boolean isCurrentSession = isCurrentSession(auth, currentTokenString);
            
            ActiveSessionDto session = ActiveSessionDto.builder()
                    .id(auth.getId())
                    .clientName(clientName)
                    .accessTokenIssuedAt(auth.getAccessTokenIssuedAt())
                    .accessTokenExpiresAt(auth.getAccessTokenExpiresAt())
                    .deviceInfo(deviceInfo)
                    .isCurrentSession(isCurrentSession)
                    .build();
            
            sessions.add(session);
        }
        
        LOGGER.info("Found {} active sessions for user", sessions.size());
        
        return ActiveSessionsResponseDto.builder()
                .tokens(sessions)
                .totalTokens(sessions.size())
                .username(currentTokenString == null ? username : null)
                .build();
    }
    
    @Override
    @Transactional
    public InvalidateSessionsResponseDto invalidateSessionsForUser(
            String username, List<String> tokenIds, String tenantId) {
        LOGGER.info("Invalidating sessions for user");
        
        // Normalize username to lowercase for case-insensitive comparison
        String normalizedUsername = username != null ? username.toLowerCase() : username;
        
        int invalidatedCount = 0;
        List<FailedSessionDto> failedSessions = new ArrayList<>();
        
        for (String tokenId : tokenIds) {
            InvalidationResult result = attemptInvalidateSession(tokenId, normalizedUsername);
            
            if (result.isSuccess()) {
                invalidatedCount++;
            } else {
                failedSessions.add(result.getFailedSession());
            }
        }
        
        LOGGER.info("Successfully invalidated {} sessions", invalidatedCount);
        
        String message = failedSessions.isEmpty() 
                ? "Sessions invalidated successfully" 
                : "Some sessions could not be invalidated";
        
        return InvalidateSessionsResponseDto.builder()
                .invalidatedSessions(invalidatedCount)
                .failedSessions(failedSessions.isEmpty() ? null : failedSessions)
                .message(message)
                .build();
    }
    
    /**
     * Attempts to invalidate a single session.
     *
     * @param tokenId the token ID to invalidate
     * @param normalizedUsername the normalized username
     * @return the invalidation result
     */
    private InvalidationResult attemptInvalidateSession(String tokenId, String normalizedUsername) {
        try {
            Authorization authorization = authorizationRepository.findById(tokenId).orElse(null);
            
            // Validate authorization exists
            if (authorization == null) {
                return InvalidationResult.failure(tokenId, "Session not found");
            }
            
            // Validate ownership
            if (!normalizedUsername.equals(authorization.getPrincipalName())) {
                return InvalidationResult.failure(tokenId, "Session does not belong to user");
            }
            
            // Validate not already invalidated
            if (isInvalidated(authorization)) {
                return InvalidationResult.failure(tokenId, "Session already invalidated");
            }
            
            // Validate not expired
            if (isExpired(authorization)) {
                return InvalidationResult.failure(tokenId, "Session already expired");
            }
            
            // Invalidate the token
            invalidateToken(authorization);
            authorizationRepository.save(authorization);
            
            return InvalidationResult.success();
            
        } catch (Exception e) {
            LOGGER.error("Error invalidating session {}: {}", tokenId, e.getMessage(), e);
            return InvalidationResult.failure(tokenId, "Internal error: " + e.getMessage());
        }
    }
    
    /**
     * Checks if an authorization is expired.
     *
     * @param authorization the authorization entity
     * @return true if expired
     */
    private boolean isExpired(Authorization authorization) {
        return authorization.getAccessTokenExpiresAt() != null 
                && authorization.getAccessTokenExpiresAt().isBefore(Instant.now());
    }
    
    /**
     * Inner class to hold invalidation result.
     */
    private static class InvalidationResult {
        private final boolean success;
        private final FailedSessionDto failedSession;
        
        private InvalidationResult(boolean success, FailedSessionDto failedSession) {
            this.success = success;
            this.failedSession = failedSession;
        }
        
        static InvalidationResult success() {
            return new InvalidationResult(true, null);
        }
        
        static InvalidationResult failure(String tokenId, String reason) {
            FailedSessionDto failedSession = FailedSessionDto.builder()
                    .tokenId(tokenId)
                    .reason(reason)
                    .build();
            return new InvalidationResult(false, failedSession);
        }
        
        boolean isSuccess() {
            return success;
        }
        
        FailedSessionDto getFailedSession() {
            return failedSession;
        }
    }
    
    /**
     * Checks if a token is not invalidated.
     *
     * @param authorization the authorization entity
     * @return true if not invalidated
     */
    private boolean isNotInvalidated(Authorization authorization) {
        return !isInvalidated(authorization);
    }
    
    /**
     * Checks if a token is invalidated.
     *
     * @param authorization the authorization entity
     * @return true if invalidated
     */
    private boolean isInvalidated(Authorization authorization) {
        String metadata = authorization.getAccessTokenMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return false;
        }
        
        try {
            JsonNode metadataNode = objectMapper.readTree(metadata);
            JsonNode invalidatedNode = metadataNode.get(INVALIDATED_KEY);
            return invalidatedNode != null && invalidatedNode.asBoolean(false);
        } catch (JsonProcessingException e) {
            LOGGER.warn("Error parsing access token metadata for token {}: {}", 
                    authorization.getId(), e.getMessage());
            return false;
        }
    }
    
    /**
     * Invalidates a token by updating its metadata.
     *
     * @param authorization the authorization entity
     */
    @SuppressWarnings("unchecked")
    private void invalidateToken(Authorization authorization) {
        try {
            String metadata = authorization.getAccessTokenMetadata();
            JsonNode metadataNode = metadata == null || metadata.isEmpty() 
                    ? objectMapper.createObjectNode() 
                    : objectMapper.readTree(metadata);
            
            Map<String, Object> metadataMap = objectMapper.convertValue(metadataNode, Map.class);
            metadataMap.put(INVALIDATED_KEY, true);
            metadataMap.put(INVALIDATION_REASON_KEY, "User requested logout");
            
            String updatedMetadata = objectMapper.writeValueAsString(metadataMap);
            authorization.setAccessTokenMetadata(updatedMetadata);
            
        } catch (JsonProcessingException e) {
            LOGGER.error("Error updating access token metadata for token {}: {}", 
                    authorization.getId(), e.getMessage());
            throw new RuntimeException("Failed to invalidate token", e);
        }
    }
    
    /**
     * Gets the client name for a client ID.
     * Client details are already cached by CacheClientService, so no additional caching is needed.
     *
     * @param clientId the client ID
     * @param tenantId the tenant ID
     * @return the client name
     */
    private String getClientName(String clientId, String tenantId) {
        try {
            ClientCacheDetails clientDetails = cacheClientService.getClientDetailsWithSync(clientId, tenantId);
            return clientDetails != null 
                    && clientDetails.getRegisteredClient() != null 
                    ? clientDetails.getRegisteredClient().getClientName() 
                    : clientId;
        } catch (Exception e) {
            LOGGER.warn("Error fetching client name for clientId {}: {}", clientId, e.getMessage());
            return clientId;
        }
    }
    
    /**
     * Parses device information from attributes JSON.
     * Checks multiple locations for browser details:
     * 1. New location: attributes.browser_details.user_agent (added by enrichAuthorizationWithBrowserDetails)
     * 2. Legacy location: attributes.java.security.Principal.details.userAgent (old format)
     *
     * @param attributesJson the attributes JSON string
     * @return the device info string
     */
    private String parseDeviceInfo(String attributesJson) {
        if (attributesJson == null || attributesJson.isEmpty()) {
            return UNKNOWN_DEVICE;
        }
        
        try {
            JsonNode attributesNode = objectMapper.readTree(attributesJson);
            
            // First, try to get browser details from the new location (browser_details)
            String userAgent = extractUserAgentFromBrowserDetails(attributesNode);
            if (userAgent != null) {
                return parseUserAgent(userAgent);
            }
            
            // Fallback: try to get from legacy location (java.security.Principal.details.userAgent)
            userAgent = extractUserAgentFromLegacyLocation(attributesNode);
            if (userAgent != null) {
                return parseUserAgent(userAgent);
            }
            
            return UNKNOWN_DEVICE;
        } catch (JsonProcessingException e) {
            LOGGER.warn("Error parsing device info from attributes: {}", e.getMessage());
            return UNKNOWN_DEVICE;
        }
    }
    
    /**
     * Extracts user agent from browser_details node.
     *
     * @param attributesNode the attributes JSON node
     * @return the user agent string or null if not found or invalid
     */
    private String extractUserAgentFromBrowserDetails(JsonNode attributesNode) {
        JsonNode browserDetailsNode = attributesNode.get("browser_details");
        if (browserDetailsNode != null && browserDetailsNode.isObject()) {
            String userAgent = browserDetailsNode.path("user_agent").asText(null);
            if (isValidUserAgent(userAgent)) {
                return userAgent;
            }
        }
        return null;
    }
    
    /**
     * Extracts user agent from legacy location (java.security.Principal.details.userAgent).
     *
     * @param attributesNode the attributes JSON node
     * @return the user agent string or null if not found or invalid
     */
    private String extractUserAgentFromLegacyLocation(JsonNode attributesNode) {
        JsonNode principalNode = attributesNode.get(DEVICE_INFO_KEY);
        if (principalNode != null && principalNode.isObject()) {
            JsonNode detailsNode = principalNode.get("details");
            if (detailsNode != null && detailsNode.isObject()) {
                String userAgent = detailsNode.path("userAgent").asText(null);
                if (isValidUserAgent(userAgent)) {
                    return userAgent;
                }
            }
        }
        return null;
    }
    
    /**
     * Checks if a user agent string is valid (not null, not empty, not "unknown").
     *
     * @param userAgent the user agent string
     * @return true if valid, false otherwise
     */
    private boolean isValidUserAgent(String userAgent) {
        return userAgent != null && !userAgent.isEmpty() && !"unknown".equals(userAgent);
    }
    
    /**
     * Parses user agent string to extract browser/client and OS.
     * Handles web browsers, mobile browsers, API clients (Postman, cURL, etc.), 
     * native mobile apps, and mobile frameworks.
     *
     * @param userAgent the user agent string
     * @return the parsed device info
     */
    private String parseUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return UNKNOWN_DEVICE;
        }
        
        OsInfo osInfo = detectOperatingSystem(userAgent);
        String client = detectClient(userAgent, osInfo.isMobile());
        
        return formatDeviceInfo(client, osInfo.getOs());
    }
    
    /**
     * Detects the operating system from user agent.
     *
     * @param userAgent the user agent string
     * @return OS information including name and mobile flag
     */
    private OsInfo detectOperatingSystem(String userAgent) {
        if (userAgent.contains("Android")) {
            return new OsInfo("Android", true);
        } else if (userAgent.contains("iPhone")) {
            return new OsInfo("iOS (iPhone)", true);
        } else if (userAgent.contains("iPad")) {
            return new OsInfo("iOS (iPad)", true);
        } else if (userAgent.contains("iPod")) {
            return new OsInfo("iOS (iPod)", true);
        } else if (userAgent.contains("Windows Phone") || userAgent.contains("Windows Mobile")) {
            return new OsInfo("Windows Phone", true);
        } else if (userAgent.contains("Windows NT") || userAgent.contains("Windows")) {
            return new OsInfo("Windows", false);
        } else if (userAgent.contains("Mac OS X") || userAgent.contains("Macintosh")) {
            return new OsInfo("macOS", false);
        } else if (userAgent.contains("Linux")) {
            return new OsInfo("Linux", false);
        } else if (userAgent.contains("CrOS")) {
            return new OsInfo("Chrome OS", false);
        }
        return new OsInfo("Unknown OS", false);
    }
    
    /**
     * Detects the client/browser from user agent.
     *
     * @param userAgent the user agent string
     * @param isMobile whether the OS is mobile
     * @return the client name
     */
    private String detectClient(String userAgent, boolean isMobile) {
        // Check mobile frameworks and native apps first
        String mobileClient = detectMobileFramework(userAgent);
        if (mobileClient != null) {
            return mobileClient;
        }
        
        // Check API testing tools
        String apiClient = detectApiClient(userAgent);
        if (apiClient != null) {
            return apiClient;
        }
        
        // Check browsers (mobile or desktop)
        return detectBrowser(userAgent, isMobile);
    }
    
    /**
     * Detects mobile frameworks and native apps.
     *
     * @param userAgent the user agent string
     * @return the framework/app name or null if not detected
     */
    private String detectMobileFramework(String userAgent) {
        String httpClient = detectHttpClient(userAgent);
        if (httpClient != null) {
            return httpClient;
        }
        
        String mobileFramework = detectMobileAppFramework(userAgent);
        if (mobileFramework != null) {
            return mobileFramework;
        }
        
        return detectNativeApp(userAgent);
    }
    
    /**
     * Detects HTTP client libraries.
     *
     * @param userAgent the user agent string
     * @return the HTTP client name or null if not detected
     */
    private String detectHttpClient(String userAgent) {
        if (userAgent.contains("okhttp")) {
            return "OkHttp Client";
        } else if (userAgent.contains("Alamofire")) {
            return "Alamofire Client";
        } else if (userAgent.contains("Retrofit")) {
            return "Retrofit Client";
        }
        return null;
    }
    
    /**
     * Detects mobile app frameworks.
     *
     * @param userAgent the user agent string
     * @return the framework name or null if not detected
     */
    private String detectMobileAppFramework(String userAgent) {
        if (userAgent.contains("Dart/") || userAgent.contains("Flutter")) {
            return "Flutter App";
        } else if (userAgent.contains("ReactNative") || userAgent.contains("React Native")) {
            return "React Native App";
        } else if (userAgent.contains("Expo")) {
            return "Expo App";
        } else if (userAgent.contains("Capacitor") || userAgent.contains("Ionic")) {
            return "Ionic/Capacitor App";
        } else if (userAgent.contains("Cordova") || userAgent.contains("PhoneGap")) {
            return "Cordova App";
        }
        return null;
    }
    
    /**
     * Detects native mobile apps.
     *
     * @param userAgent the user agent string
     * @return the native app platform or null if not detected
     */
    private String detectNativeApp(String userAgent) {
        String lowerUserAgent = userAgent.toLowerCase();
        if (lowerUserAgent.contains("androidapp") 
                || lowerUserAgent.contains("nativeandroid")) {
            return "Android App";
        } else if (lowerUserAgent.contains("iosapp") 
                || lowerUserAgent.contains("nativeios")) {
            return "iOS App";
        }
        return null;
    }
    
    /**
     * Detects API testing and development tools.
     *
     * @param userAgent the user agent string
     * @return the API client name or null if not detected
     */
    private String detectApiClient(String userAgent) {
        if (userAgent.contains("PostmanRuntime")) {
            return "Postman";
        } else if (userAgent.contains(INSOMNIA)) {
            return INSOMNIA;
        } else if (userAgent.startsWith("curl/") || userAgent.contains("curl")) {
            return "cURL";
        } else if (userAgent.contains(HTTPIE)) {
            return HTTPIE;
        } else if (userAgent.contains("Python-urllib") || userAgent.contains("python-requests")) {
            return "Python Client";
        } else if (userAgent.contains("Java/") || userAgent.contains("Apache-HttpClient")) {
            return "Java Client";
        }
        return null;
    }
    
    /**
     * Detects browser from user agent.
     *
     * @param userAgent the user agent string
     * @param isMobile whether the OS is mobile
     * @return the browser name
     */
    private String detectBrowser(String userAgent, boolean isMobile) {
        // Regional mobile browsers (check first as they have priority)
        String regionalBrowser = detectRegionalBrowser(userAgent);
        if (regionalBrowser != null) {
            return regionalBrowser;
        }
        
        // Mobile-specific browsers
        if (isMobile) {
            String mobileBrowser = detectMobileBrowser(userAgent);
            if (mobileBrowser != null) {
                return mobileBrowser;
            }
        }
        
        // Desktop browsers (also fallback for mobile)
        String desktopBrowser = detectDesktopBrowser(userAgent);
        if (desktopBrowser != null) {
            return desktopBrowser;
        }
        
        // Fallback: extract first token
        return extractBrowserFromToken(userAgent);
    }
    
    /**
     * Detects mobile-specific browsers.
     *
     * @param userAgent the user agent string
     * @return the mobile browser name or null if not detected
     */
    private String detectMobileBrowser(String userAgent) {
        if (userAgent.contains(OPERA) || userAgent.contains("OPR/")) {
            return "Opera Mobile";
        } else if (userAgent.contains("Firefox/")) {
            return "Firefox Mobile";
        } else if (userAgent.contains("Chrome/") && !userAgent.contains("Edg")) {
            return "Chrome Mobile";
        } else if (userAgent.contains("Safari/") && !userAgent.contains("Chrome")) {
            return "Safari Mobile";
        }
        return null;
    }
    
    /**
     * Detects regional mobile browsers.
     *
     * @param userAgent the user agent string
     * @return the regional browser name or null if not detected
     */
    private String detectRegionalBrowser(String userAgent) {
        if (userAgent.contains("SamsungBrowser") || userAgent.contains("Samsung Browser")) {
            return "Samsung Browser";
        } else if (userAgent.contains("UCBrowser") || userAgent.contains("UC Browser")) {
            return "UC Browser";
        }
        return null;
    }
    
    /**
     * Detects desktop browsers.
     *
     * @param userAgent the user agent string
     * @return the desktop browser name or null if not detected
     */
    private String detectDesktopBrowser(String userAgent) {
        if (userAgent.contains("Edg/")) {
            return "Edge";
        } else if (userAgent.contains("Chrome/")) {
            return "Chrome";
        } else if (userAgent.contains("Safari/")) {
            return "Safari";
        } else if (userAgent.contains("Firefox/")) {
            return "Firefox";
        } else if (userAgent.contains("MSIE") || userAgent.contains("Trident/")) {
            return "Internet Explorer";
        } else if (userAgent.contains(OPERA) || userAgent.contains("OPR/")) {
            return OPERA;
        }
        return null;
    }
    
    /**
     * Extracts browser name from first token as fallback.
     *
     * @param userAgent the user agent string
     * @return the extracted browser name or "Unknown Client"
     */
    private String extractBrowserFromToken(String userAgent) {
        String[] parts = userAgent.split("[/\\s]");
        if (parts.length > 0 && !parts[0].isEmpty()) {
            return parts[0];
        }
        return "Unknown Client";
    }
    
    /**
     * Formats device info based on client type.
     *
     * @param client the client name
     * @param os the operating system name
     * @return formatted device info string
     */
    private String formatDeviceInfo(String client, String os) {
        if (client.equals("Postman") || client.equals(INSOMNIA) || client.equals("cURL") 
                || client.equals(HTTPIE) || client.endsWith("Client")) {
            return os.equals("Unknown OS") ? client : client + " (" + os + ")";
        } else if (client.endsWith("App")) {
            return client + " on " + os;
        } else {
            return client + " on " + os;
        }
    }
    
    /**
     * Inner class to hold OS information.
     */
    private static class OsInfo {
        private final String os;
        private final boolean mobile;
        
        OsInfo(String os, boolean mobile) {
            this.os = os;
            this.mobile = mobile;
        }
        
        public String getOs() {
            return os;
        }
        
        public boolean isMobile() {
            return mobile;
        }
    }
    
    /**
     * Checks if an authorization matches the current session.
     *
     * @param authorization the authorization entity
     * @param currentTokenString the current JWT token string
     * @return true if it's the current session, false otherwise
     */
    private Boolean isCurrentSession(Authorization authorization, String currentTokenString) {
        if (currentTokenString == null || currentTokenString.isEmpty()) {
            return false;
        }
        
        try {
            Claims claims = jwtTokenValidator.getClaimsFromToken(currentTokenString);
            
            String tokenUsername = claims.get("username", String.class);
            String tokenClientId = extractClientIdFromClaims(claims);
            
            // Normalize username to lowercase for case-insensitive comparison
            String normalizedTokenUsername = tokenUsername != null ? tokenUsername.toLowerCase() : null;
            
            // Convert Date to Instant and truncate to seconds for comparison
            Instant tokenIat = truncateToSeconds(claims.getIssuedAt());
            Instant tokenExp = truncateToSeconds(claims.getExpiration());
            
            // Truncate database timestamps to seconds for comparison
            Instant authIat = truncateToSeconds(authorization.getAccessTokenIssuedAt());
            Instant authExp = truncateToSeconds(authorization.getAccessTokenExpiresAt());
            
            boolean usernameMatches = normalizedTokenUsername != null 
                    && normalizedTokenUsername.equals(authorization.getPrincipalName());
            boolean clientMatches = tokenClientId != null 
                    && tokenClientId.equals(authorization.getRegisteredClientId());
            boolean iatMatches = tokenIat != null && authIat != null
                    && tokenIat.equals(authIat);
            boolean expMatches = tokenExp != null && authExp != null
                    && tokenExp.equals(authExp);
            
            return usernameMatches && clientMatches && iatMatches && expMatches;
        } catch (Exception e) {
            LOGGER.error("Error identifying current session: {}", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Extracts the client ID from JWT claims.
     * Handles both String and Collection (LinkedHashSet) audience claim types.
     *
     * @param claims the JWT claims
     * @return the client ID or null if not found
     */
    private String extractClientIdFromClaims(Claims claims) {
        Object audClaim = claims.get("aud");
        if (audClaim instanceof String) {
            return (String) audClaim;
        } else if (audClaim instanceof java.util.Collection) {
            java.util.Collection<?> audCollection = (java.util.Collection<?>) audClaim;
            if (!audCollection.isEmpty()) {
                return audCollection.iterator().next().toString();
            }
        }
        return null;
    }
    
    /**
     * Truncates a timestamp to seconds precision.
     * JWT tokens have second precision, but database timestamps have nanosecond precision.
     *
     * @param instant the instant to truncate
     * @return the truncated instant or null if input is null
     */
    private Instant truncateToSeconds(Instant instant) {
        return instant != null 
                ? instant.truncatedTo(java.time.temporal.ChronoUnit.SECONDS) 
                : null;
    }
    
    /**
     * Truncates a date to seconds precision by converting to Instant.
     *
     * @param date the date to truncate
     * @return the truncated instant or null if input is null
     */
    private Instant truncateToSeconds(Date date) {
        return date != null 
                ? date.toInstant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS) 
                : null;
    }
}
