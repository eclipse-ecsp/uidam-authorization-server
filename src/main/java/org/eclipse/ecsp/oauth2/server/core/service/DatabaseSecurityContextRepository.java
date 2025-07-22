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

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.entities.AuthorizationSecurityContext;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationSecurityContextRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.eclipse.ecsp.oauth2.server.core.utils.ObjectMapperUtils.parseMap;
import static org.eclipse.ecsp.oauth2.server.core.utils.ObjectMapperUtils.writeMap;

/**
 * A SecurityContextRepository implementation which stores the security context in the Database between requests.
 * This class is responsible for managing the security context for each session.
 */
public class DatabaseSecurityContextRepository implements SecurityContextRepository {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseSecurityContextRepository.class);

    public static final String PRINCIPAL = "principal";
    public static final int MILLI_SEC = 1000;
    public static final int SEC = 60;
    public static final String MIN = "m";
    public static final String PROTECTED_CREDS = "[PROTECTED]";

    private final AuthorizationSecurityContextRepository authorizationSecurityContextRepository;

    private final TenantConfigurationService tenantConfigurationService;

    private final String sessionTimeout;

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
        .getContextHolderStrategy();

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * This is a parameterized constructor for the DatabaseSecurityContextRepository class.
     * It initializes the AuthorizationSecurityContextRepository instance, retrieves the tenant properties, and sets the
     * session timeout.
     * It also registers the security modules with the ObjectMapper.
     *
     * @param authorizationSecurityContextRepository an instance of AuthorizationSecurityContextRepository, used to
     *                                               interact with the security context stored in the database
     * @param tenantConfigurationService an instance of TenantConfigurationService, used to retrieve the tenant
     *                                   properties
     * @param sessionTimeout a string representing the session timeout value
     */
    public DatabaseSecurityContextRepository(AuthorizationSecurityContextRepository
                                                 authorizationSecurityContextRepository,
                                             TenantConfigurationService tenantConfigurationService,
                                             String sessionTimeout) {
        Assert.notNull(authorizationSecurityContextRepository, "authorizationSecurityContextRepository cannot be null");
        this.authorizationSecurityContextRepository = authorizationSecurityContextRepository;
        this.tenantConfigurationService = tenantConfigurationService;
        this.sessionTimeout = sessionTimeout;

        ClassLoader classLoader = DatabaseSecurityContextRepository.class.getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
    }

    /**
     * This method is used to load the SecurityContext for a given HttpRequestResponseHolder.
     * It delegates to the loadDeferredContext method.
     *
     * @param requestResponseHolder the HttpRequestResponseHolder
     * @return the SecurityContext for the given HttpRequestResponseHolder
     */
    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        return loadDeferredContext(requestResponseHolder.getRequest()).get();
    }

    /**
     * This method is used to load the DeferredSecurityContext for a given HttpServletRequest.
     * It creates a SupplierDeferredSecurityContext with a supplier that reads the SecurityContext from the request.
     *
     * @param request the HttpServletRequest
     * @return the DeferredSecurityContext for the given HttpServletRequest
     */
    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        Supplier<SecurityContext> supplier = () -> readSecurityContext(request);
        return new SupplierDeferredSecurityContext(supplier, this.securityContextHolderStrategy);
    }

    /**
     * This method is used to save the SecurityContext for a given HttpServletRequest and HttpServletResponse.
     * If the context is null or the requested session id is empty, it does nothing.
     * If the context is equal to an empty context, it unauthenticates the context in the database.
     * Otherwise, it authenticates the context in the database.
     *
     * @param context the SecurityContext
     * @param request the HttpServletRequest
     * @param response the HttpServletResponse
     */
    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        String requestedSessionId = request.getSession().getId();
        if (context == null) {
            LOGGER.debug("Null SecurityContext for Session Id: {}", requestedSessionId);
            return;
        }
        if (StringUtils.isEmpty(requestedSessionId)) {
            LOGGER.debug("No Session currently exists");
            return;
        }
        SecurityContext emptyContext = generateNewContext();
        if (emptyContext.equals(context)) {
            unauthenticatedContextInDb(requestedSessionId);
        } else {
            authenticatedContextInDb(context, request);
        }
    }

    /**
     * This method is used to authenticate the SecurityContext in the database.
     * It retrieves or creates an AuthorizationSecurityContext for the requested session id and updates it with the
     * information from the SecurityContext.
     * It then saves the updated AuthorizationSecurityContext in the database.
     *
     * @param context the SecurityContext
     * @param request the HttpServletRequest
     */
    private void authenticatedContextInDb(SecurityContext context, HttpServletRequest request) {
        String requestedSessionId = request.getSession().getId();
        LOGGER.info("Storing Authenticated SecurityContext to Database for Session Id: {}", requestedSessionId);
        Timestamp currentTimestamp = Timestamp.from(Instant.now());
        AuthorizationSecurityContext authorizationSecurityContext = getSecurityContextFromDb(requestedSessionId);
        if (authorizationSecurityContext == null) {
            authorizationSecurityContext = new AuthorizationSecurityContext();
            authorizationSecurityContext.setSessionId(requestedSessionId);
            authorizationSecurityContext.setCreatedDate(currentTimestamp);
        }
        Authentication authentication = context.getAuthentication();
        if (authentication.getPrincipal() instanceof String principalName) {
            authorizationSecurityContext.setPrincipal(principalName);
        }
        if (authentication.getPrincipal() instanceof OAuth2User oauth2User) {
            Map<String, Object> principal = new HashMap<>();
            principal.put(PRINCIPAL, oauth2User);
            authorizationSecurityContext.setPrincipal(writeMap(this.objectMapper, principal));
        }
        String accountName = null;
        if (authentication instanceof CustomUserPwdAuthenticationToken customUserPwdAuthenticationToken) {
            accountName = customUserPwdAuthenticationToken.getAccountName();
        }
        if (StringUtils.isEmpty(accountName)) {
            TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
            accountName = tenantProperties.getAccount().getAccountName();
        }
        authorizationSecurityContext.setAccountName(accountName);
        if (authentication instanceof OAuth2AuthenticationToken oauth2AuthenticationToken) {
            authorizationSecurityContext.setAuthorizedClientRegistrationId(oauth2AuthenticationToken
                    .getAuthorizedClientRegistrationId());
        } else {
            authorizationSecurityContext.setAuthorizedClientRegistrationId(null);
        }
        authorizationSecurityContext.setAuthenticated(authentication.isAuthenticated());
        String grantedAuthoritiesStr = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
        authorizationSecurityContext.setAuthorities(grantedAuthoritiesStr);
        authorizationSecurityContext.setRemoteIpAddress(request.getRemoteAddr());
        authorizationSecurityContext.setUpdatedDate(currentTimestamp);
        authorizationSecurityContextRepository.save(authorizationSecurityContext);
        LOGGER.debug("Stored Authenticated SecurityContext to Database: {}", authorizationSecurityContext);
    }

    /**
     * This method is used to unauthenticate the SecurityContext in the database.
     * It retrieves the AuthorizationSecurityContext for the session id and sets its authenticated flag to false.
     * It then saves the updated AuthorizationSecurityContext in the database.
     *
     * @param sessionId the session id
     */
    public void unauthenticatedContextInDb(String sessionId) {
        LOGGER.info("Updating Unauthenticated SecurityContext to Database for Session Id: {}", sessionId);
        AuthorizationSecurityContext authorizationSecurityContext = getSecurityContextFromDb(sessionId);
        if (authorizationSecurityContext != null) {
            authorizationSecurityContext.setAuthenticated(false);
            authorizationSecurityContext.setUpdatedDate(Timestamp.from(Instant.now()));
            authorizationSecurityContextRepository.save(authorizationSecurityContext);
            LOGGER.debug("Updated Unauthenticated SecurityContext to Database: {}", authorizationSecurityContext);
        }
    }

    /**
     * This method is used to check if a SecurityContext exists for a given HttpServletRequest.
     * It reads the SecurityContext from the request and checks if it is not null and has an authentication.
     *
     * @param request the HttpServletRequest
     * @return true if a SecurityContext exists for the request, false otherwise
     */
    @Override
    public boolean containsContext(HttpServletRequest request) {
        boolean contains = false;
        SecurityContext securityContext = readSecurityContext(request);
        if (securityContext != null && securityContext.getAuthentication() != null) {
            contains = true;
        }
        return contains;
    }

    /**
     * This method is used to read the SecurityContext for a given HttpServletRequest.
     * It retrieves the AuthorizationSecurityContext for the requested session id from the database and converts it to a
     * SecurityContext.
     *
     * @param request the HttpServletRequest
     * @return the SecurityContext for the request, or null if none exists
     */
    private SecurityContext readSecurityContext(HttpServletRequest request) {
        String requestedSessionId = request.getSession().getId();
        if (StringUtils.isEmpty(requestedSessionId)) {
            LOGGER.debug("No Session currently exists");
            return null;
        }
        LOGGER.info("Retrieving SecurityContext for Session Id: {}", requestedSessionId);
        AuthorizationSecurityContext authorizationSecurityContext = getSecurityContextFromDb(requestedSessionId);
        if (authorizationSecurityContext == null) {
            LOGGER.debug("Did not find SecurityContext in Database for Session Id: {}", requestedSessionId);
            return null;
        }
        if (Boolean.FALSE.equals(authorizationSecurityContext.getAuthenticated())) {
            // False Authenticated flag when fixed session timeout or token revoke
            LOGGER.info("Authenticated flag false for Session Id: {}", requestedSessionId);
            return null; // Redirect to login page
        }
        Timestamp currentDateTime = Timestamp.from(Instant.now());
        Timestamp updatedDateTime = authorizationSecurityContext.getUpdatedDate();
        long diffInMin = (currentDateTime.getTime() - updatedDateTime.getTime()) / MILLI_SEC / SEC;
        long sessionTimeoutMin = Long.parseLong(sessionTimeout.substring(0, sessionTimeout.indexOf(MIN)));
        LOGGER.info("diffInMin: {} and sessionTimeoutMin: {} for Session Id: {}", diffInMin, sessionTimeoutMin,
            requestedSessionId);
        if (diffInMin < sessionTimeoutMin) { // Fixed session timeout
            String grantedAuthoritiesStr = authorizationSecurityContext.getAuthorities();
            List<SimpleGrantedAuthority> grantedAuthorities = new ArrayList<>();
            if (StringUtils.isNotEmpty(grantedAuthoritiesStr)) {
                List<String> grantedAuthorityStrList = Arrays.stream(grantedAuthoritiesStr.split(",")).toList();
                grantedAuthorities = grantedAuthorityStrList.stream().map(SimpleGrantedAuthority::new)
                    .toList();
            }
            AbstractAuthenticationToken abstractAuthenticationToken = null;
            if (StringUtils.isEmpty(authorizationSecurityContext.getAuthorizedClientRegistrationId())) {
                abstractAuthenticationToken = new CustomUserPwdAuthenticationToken(
                    authorizationSecurityContext.getPrincipal(), PROTECTED_CREDS,
                    authorizationSecurityContext.getAccountName(), grantedAuthorities);
            } else {
                Map<String, Object> principal = new HashMap<>(parseMap(this.objectMapper,
                    authorizationSecurityContext.getPrincipal()));
                OAuth2User oauth2User = (OAuth2User) principal.get(PRINCIPAL);
                abstractAuthenticationToken = new OAuth2AuthenticationToken(oauth2User,
                    grantedAuthorities, authorizationSecurityContext.getAuthorizedClientRegistrationId());
            }
            WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails(request.getRemoteAddr(),
                requestedSessionId);
            abstractAuthenticationToken.setDetails(webAuthenticationDetails);
            SecurityContext securityContext = generateNewContext();
            securityContext.setAuthentication(abstractAuthenticationToken);
            LOGGER.debug("Retrieved SecurityContext: {}", securityContext);
            return securityContext;
        } else {
            LOGGER.info("Session timeout for Session Id: {}", requestedSessionId);
            unauthenticatedContextInDb(requestedSessionId); // Authenticated flag false after fixed session timeout
            return null; // Redirect to login page
        }
    }

    /**
     * This method is used to get the AuthorizationSecurityContext for a given session id from the database.
     *
     * @param sessionId the session id
     * @return the AuthorizationSecurityContext for the session id, or null if none exists
     */
    private AuthorizationSecurityContext getSecurityContextFromDb(String sessionId) {
        LOGGER.debug("Retrieving SecurityContext from Database for Session Id: {}", sessionId);
        Optional<AuthorizationSecurityContext> authorizationSecurityContextOptional =
            authorizationSecurityContextRepository.findBySessionId(sessionId);
        if (authorizationSecurityContextOptional.isEmpty()) {
            LOGGER.debug("Did not find SecurityContext in Database for Session Id: {}", sessionId);
            return null;
        }
        AuthorizationSecurityContext authorizationSecurityContext = authorizationSecurityContextOptional.get();
        LOGGER.debug("Retrieved SecurityContext from Database: {}", authorizationSecurityContext);
        return authorizationSecurityContext;
    }

    /**
     * This method is used to generate a new empty SecurityContext.
     *
     * @return a new empty SecurityContext
     */
    private SecurityContext generateNewContext() {
        return this.securityContextHolderStrategy.createEmptyContext();
    }

    /**
     * This method is used to set the SecurityContextHolderStrategy.
     *
     * @param securityContextHolderStrategy the SecurityContextHolderStrategy
     */
    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }

}