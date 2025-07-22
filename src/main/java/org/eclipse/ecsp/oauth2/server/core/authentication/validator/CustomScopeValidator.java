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

package org.eclipse.ecsp.oauth2.server.core.authentication.validator;

import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.CommonMethodsUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;


/**
 * The CustomScopeValidator class implements the Consumer interface with
 * OAuth2AuthorizationCodeRequestAuthenticationContext as its type.
 * It is used to validate the scopes in an OAuth2 authorization code request.
 * This class is responsible for validating the scopes requested by the client during the OAuth2 authorization code
 * request.
 * It checks if the requested scopes are allowed for the client and if the user has the necessary permissions for the
 * requested scopes.
 */
@Service
public class CustomScopeValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomScopeValidator.class);

    private TenantConfigurationService tenantConfigurationService;
    
    CacheClientUtils cacheClientUtils;

    /**
     * constructor to initialize the CustomScopeValidator with the required services.
     *
     * @param tenantConfigurationService the service to get tenant configurations.
     * @param cacheClientUtils the utility class for cache operations related to clients.
     */
    @Autowired
    public CustomScopeValidator(TenantConfigurationService tenantConfigurationService,
            CacheClientUtils cacheClientUtils) {
        this.tenantConfigurationService = tenantConfigurationService;
        this.cacheClientUtils = cacheClientUtils;
    }

    /**
     * This method is overridden from Consumer interface.
     * It validates the scopes in the OAuth2 authorization code request.
     *
     * @param authenticationContext the context of the OAuth2 authorization code request.
     */
    @Override
    public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
            authenticationContext.getAuthentication();
        RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
        boolean isFederatedUser = false;
        Set<String> requestedScopes = authorizationCodeRequestAuthentication.getScopes();
        Set<String> allowedScopes = registeredClient.getScopes();
        Set<String> requestScopesWithoutOidcScopes = requestedScopes.stream()
            .filter(s -> !s.equals(OidcScopes.OPENID)).collect(Collectors.toSet());
        if (!requestScopesWithoutOidcScopes.isEmpty()
            && !allowedScopes.containsAll(requestScopesWithoutOidcScopes)) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE, "OAuth 2.0 Parameter: "
                + OAuth2ParameterNames.SCOPE, null);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,
                authorizationCodeRequestAuthentication);
        }

        Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
        if (principal instanceof OAuth2AuthenticationToken) {
            LOGGER.debug("Federated user authentication");
            isFederatedUser = true;
        }
        if (principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass())
            && principal.isAuthenticated() && !isFederatedUser) {
            customScopeValidation(authenticationContext, authorizationCodeRequestAuthentication,
                requestScopesWithoutOidcScopes, principal);
        }
    }

    /**
     * This method performs custom scope validation.
     *
     * @param authenticationContext the context of the OAuth2 authorization code request.
     * @param authCodeRequestAuthentication the OAuth2 authorization code request authentication token.
     * @param requestScopesWithoutOidcScopes the requested scopes without OIDC scopes.
     * @param principal the principal (user) making the request.
     */
    private void customScopeValidation(OAuth2AuthorizationCodeRequestAuthenticationContext
                                           authenticationContext,
                                       OAuth2AuthorizationCodeRequestAuthenticationToken
                                           authCodeRequestAuthentication,
                                       Set<String> requestScopesWithoutOidcScopes,
                                       Authentication principal) {
        ClientCacheDetails clientDetails = cacheClientUtils.getClientDetails(
            authenticationContext.getRegisteredClient().getClientId());

        if (!CommonMethodsUtils.isUserScopeValidationRequired(
                (null != clientDetails ? clientDetails.getClientType() : null),
                tenantConfigurationService.getTenantProperties().getClient().getOauthScopeCustomization())) {

            LOGGER.debug("Scope Validation for username {} not required", principal.getName());
        } else {
            scopeValidationForUser(authCodeRequestAuthentication, requestScopesWithoutOidcScopes, principal);
        }
    }

    /**
     * This method validates the scopes for a user.
     *
     * @param authorizationCodeRequestAuthentication the OAuth2 authorization code request authentication token.
     * @param requestScopesWithoutOidcScopes the requested scopes without OIDC scopes.
     * @param principal the principal (user) making the request.
     */
    private void scopeValidationForUser(
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
        Set<String> requestScopesWithoutOidcScopes, Authentication principal) {
        LOGGER.debug("Validating scopes for username {}", principal.getName());
        for (String requestedScope : requestScopesWithoutOidcScopes) {
            List<GrantedAuthority> grantedAuthorities = (List<GrantedAuthority>)
                ((CustomUserPwdAuthenticationToken) authorizationCodeRequestAuthentication.getPrincipal())
                    .getAuthorities();
            Set<String> userAllowedScopes = grantedAuthorities.stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
            if (!userAllowedScopes.contains(requestedScope)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE, "OAuth 2.0 Parameter: "
                    + OAuth2ParameterNames.SCOPE, null);
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,
                    authorizationCodeRequestAuthentication);
            }
        }
    }

}