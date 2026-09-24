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

package org.eclipse.ecsp.oauth2.server.core.config;

import org.eclipse.ecsp.audit.logger.AuditLogger;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.client.UserManagementClient;
import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.AccountProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ClientProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ExternalIdpRegisteredClient;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.IdTokenProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ScopePreference;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ScopeRoleMapping;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.SignupClientConfig;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UserProperties;
import org.eclipse.ecsp.oauth2.server.core.metrics.AuthorizationMetricsService;
import org.eclipse.ecsp.oauth2.server.core.request.dto.FederatedUserDto;
import org.eclipse.ecsp.oauth2.server.core.response.UserDetailsResponse;
import org.eclipse.ecsp.oauth2.server.core.service.ClaimMappingService;
import org.eclipse.ecsp.oauth2.server.core.service.ScopeRoleClaimMappingService;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.test.TestOauth2Authorizations;
import org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLAIM_EXTERNAL_IDP_ID_TOKEN;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.getUser;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.getUserWithEmptyScope;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.jwsHeader;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.jwtClaimsSet;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.jwtClaimsSetWithCustomScope;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.jwtClaimsSetWithScope;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ATTRIBUTE_SUB;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.REGISTRATION_ID_GOOGLE;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_ACCOUNT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.TEST_USER_NAME;
import static org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients.registeredClient;
import static org.eclipse.ecsp.oauth2.server.core.test.TestRegisteredClients.registeredClientWithEmptyScope;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;

/**
 * This class tests the functionality of the ClaimsConfigManager.
 */
@ExtendWith(MockitoExtension.class)
class ClaimsConfigManagerTest {
    private static final long EXTERNAL_IDP_ID_TOKEN_TTL_SECONDS = 300L;
    private static final long TEST_UPDATED_AT = 1788933537L;
    private static final int TEST_LOYALTY_LEVEL = 7;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private CacheClientUtils cacheClientUtils;

    @Mock
    private UserManagementClient userManagementClient;

    @Mock
    private AuditLogger auditLogger;

    @Mock
    private ClaimMappingService claimMappingService;

    @Mock
    private AuthorizationMetricsService authorizationMetricsService;

    @Mock
    private ScopeRoleClaimMappingService scopeRoleClaimMappingService;

    @InjectMocks
    private ClaimsConfigManager claimsConfigManager;

    private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

    /**
     * This test method tests the scenario where the token customization for
     * authorization code grant access token type is successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * Verifies {@code custom-attributes-for-claims} resolution: an unprefixed key resolves against
     * mandatory {@link UserDetailsResponse} fields, while an {@code ATTR_}-prefixed key resolves
     * against the dynamic/custom {@code additionalAttributes} map.
     */
    @Test
    void jwtTokenCustomizerAppliesMandatoryAndCustomAttributeClaims() {
        TenantProperties tenantProperties = createMockTenantProperties();
        SignupClientConfig signupClientConfig = new SignupClientConfig();
        signupClientConfig.setClientId("client-1");
        signupClientConfig.setCustomAttributesForClaims("userName,ATTR_firstName");
        tenantProperties.setSignupConfigList(List.of(signupClientConfig));
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).build();

        jwtCustomizer.customize(context);

        // Unprefixed "userName" resolves against the mandatory UserDetailsResponse field.
        assertEquals("testUser", context.getClaims().build().getClaim("userName"));
        // "ATTR_firstName" resolves (after stripping the prefix) against additionalAttributes.
        assertEquals("first", context.getClaims().build().getClaim("firstName"));
    }

    /**
     * This test method tests the scenario where the token customization for
     * authorization code grant access token type with scope is successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType2() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSetWithScope())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for
     * authorization code grant access token type with multi-role client and user
     * with empty scope is successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType3() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUserWithEmptyScope()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for
     * authorization code grant access token type with multi-role client is
     * successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType4() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for authorization code grant access token type
     * with empty scope and multi-role client is successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType5() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
            TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
            OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
            "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
            .registeredClient(registeredClient)
            .principal(principal)
            .authorization(authorization)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrant(authorizationGrant)
            .put("custom-key-1", "custom-value-1")
            .context(ctx -> ctx.put("custom-key-2", "custom-value-2"))
            .build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for authorization code grant access token type
     * with empty scope and multi-role client and scope is successful.
     */
    @Test
    void jwtTokenCustomizerForAuthCodeGrantAccessTokenType6() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
            TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
            OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
            "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSetWithScope())
            .registeredClient(registeredClient)
            .principal(principal)
            .authorization(authorization)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrant(authorizationGrant)
            .put("custom-key-1", "custom-value-1")
            .context(ctx -> ctx.put("custom-key-2", "custom-value-2"))
            .build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     *  This test method tests the scenario where the token customization for
     * authorization code grant ID token type is successful.
     */
    @Test
    void jwtTokenCustomizerForInternalIdTokenType_UsesConfiguredUidamClaims() {
        TenantProperties tenantProperties = createMockTenantProperties();
        IdTokenProperties idTokenProperties = new IdTokenProperties();
        idTokenProperties.setAdditionalClaims(
                "email,profile,loyaltyLevel,newsletterOptIn,favoriteBrands,emptyAttribute,iss");
        tenantProperties.getClient().setIdTokenProperties(idTokenProperties);
        lenient().when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        
        // The user-management response contains both fixed user columns and database-backed custom attributes.
        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setId("user-id-123");
        userDetailsResponse.setUserName(TEST_USER_NAME);
        userDetailsResponse.setEmail("internal-user@example.com");
        userDetailsResponse.setAdditionalAttributes(Map.of(
                "profile", "internal-profile",
                "loyaltyLevel", TEST_LOYALTY_LEVEL,
                "newsletterOptIn", false,
                "favoriteBrands", List.of("brand-a", "brand-b"),
                "emptyAttribute", "",
                "notConfigured", "must-not-be-exposed"));
        
        doReturn(userDetailsResponse).when(userManagementClient).getUserDetailsByUsername(TEST_USER_NAME,
                TEST_ACCOUNT_NAME);

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(new OAuth2TokenType("id_token"))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        jwtCustomizer.customize(context);

        assertEquals("internal-user@example.com", context.getClaims().build().getClaim("email"));
        assertEquals("subject", context.getClaims().build().getSubject());
        assertEquals("internal-profile", context.getClaims().build().getClaim("profile"));
        assertEquals(Integer.valueOf(TEST_LOYALTY_LEVEL),
                context.getClaims().build().getClaim("loyaltyLevel"));
        assertEquals(false, context.getClaims().build().getClaim("newsletterOptIn"));
        assertEquals(List.of("brand-a", "brand-b"), context.getClaims().build().getClaim("favoriteBrands"));
        assertEquals("https://provider.com", context.getClaims().build().getClaim("iss").toString());
        assertNull(context.getClaims().build().getClaim("emptyAttribute"));
        assertNull(context.getClaims().build().getClaim("notConfigured"));
        assertEquals("Pxa-1wifRlPl7yG_0oJNfw",
                context.getClaims().build().getClaim(IdTokenClaimNames.AT_HASH));
        assertEquals("VpTQii5T_8rgwxA-Wtb2Bw",
                context.getClaims().build().getClaim(IdTokenClaimNames.C_HASH));
        org.junit.jupiter.api.Assertions.assertNotNull(context.getClaims().build().getClaim("jti"));
        verify(userManagementClient).getUserDetailsByUsername(TEST_USER_NAME, TEST_ACCOUNT_NAME);
    }

    @Test
    void jwtTokenCustomizerForIdTokenType_PopulatesClaimsSelectedByOidcScopes() {
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();

        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setId("user-id-123");
        userDetailsResponse.setUserName("ada");
        userDetailsResponse.setEmail("ada@example.com");
        Map<String, Object> attributes = userDetailsResponse.getAdditionalAttributes();
        attributes.put("firstName", "Ada");
        attributes.put("lastName", "Lovelace");
        attributes.put("middleName", "Byron");
        attributes.put("nickName", "Enchantress of Numbers");
        attributes.put("profile", "https://example.com/users/ada");
        attributes.put("picture", "https://example.com/users/ada.jpg");
        attributes.put("website", "https://example.com/ada");
        attributes.put("gender", "female");
        attributes.put("birthDate", "1815-12-10");
        attributes.put("timeZone", "Europe/London");
        attributes.put("locale", "en-GB");
        attributes.put("updatedAt", TEST_UPDATED_AT);
        attributes.put("emailVerified", true);
        attributes.put("address1", "12 St James's Square");
        attributes.put("address2", "Westminster");
        attributes.put("city", "London");
        attributes.put("state", "England");
        attributes.put("postalCode", "SW1Y 4LB");
        attributes.put("country", "GB");
        attributes.put("phoneNumber", "+44 20 1234 5678");
        attributes.put("phoneNumberVerified", false);
        doReturn(userDetailsResponse).when(userManagementClient)
                .getUserDetailsByUsername(TEST_USER_NAME, TEST_ACCOUNT_NAME);

        Set<String> scopes = Set.of(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL,
                OidcScopes.ADDRESS, OidcScopes.PHONE);
        JwtEncodingContext context = buildInternalIdTokenContext(scopes);
        jwtCustomizer.customize(context);

        Map<String, Object> claims = context.getClaims().build().getClaims();
        assertEquals("Ada Lovelace", claims.get(StandardClaimNames.NAME));
        assertEquals("Ada", claims.get(StandardClaimNames.GIVEN_NAME));
        assertEquals("Lovelace", claims.get(StandardClaimNames.FAMILY_NAME));
        assertEquals("Byron", claims.get(StandardClaimNames.MIDDLE_NAME));
        assertEquals("Enchantress of Numbers", claims.get(StandardClaimNames.NICKNAME));
        assertEquals("ada", claims.get(StandardClaimNames.PREFERRED_USERNAME));
        assertEquals("https://example.com/users/ada", claims.get(StandardClaimNames.PROFILE));
        assertEquals("https://example.com/users/ada.jpg", claims.get(StandardClaimNames.PICTURE));
        assertEquals("https://example.com/ada", claims.get(StandardClaimNames.WEBSITE));
        assertEquals("female", claims.get(StandardClaimNames.GENDER));
        assertEquals("1815-12-10", claims.get(StandardClaimNames.BIRTHDATE));
        assertEquals("Europe/London", claims.get(StandardClaimNames.ZONEINFO));
        assertEquals("en-GB", claims.get(StandardClaimNames.LOCALE));
        assertEquals(TEST_UPDATED_AT, claims.get(StandardClaimNames.UPDATED_AT));
        assertEquals("ada@example.com", claims.get(StandardClaimNames.EMAIL));
        assertEquals(true, claims.get(StandardClaimNames.EMAIL_VERIFIED));
        assertEquals("+44 20 1234 5678", claims.get(StandardClaimNames.PHONE_NUMBER));
        assertEquals(false, claims.get(StandardClaimNames.PHONE_NUMBER_VERIFIED));
        assertEquals(Map.of(
                "street_address", "12 St James's Square\nWestminster",
                "locality", "London",
                "region", "England",
                "postal_code", "SW1Y 4LB",
                "country", "GB"), claims.get(StandardClaimNames.ADDRESS));
    }

    @Test
    void jwtTokenCustomizerForIdTokenType_DoesNotExposeClaimsForUnrequestedOidcScopes() {
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();

        UserDetailsResponse userDetailsResponse = new UserDetailsResponse();
        userDetailsResponse.setUserName("ada");
        userDetailsResponse.setEmail("ada@example.com");
        userDetailsResponse.getAdditionalAttributes().put("firstName", "Ada");
        userDetailsResponse.getAdditionalAttributes().put("phoneNumber", "+44 20 1234 5678");
        userDetailsResponse.getAdditionalAttributes().put("city", "London");
        doReturn(userDetailsResponse).when(userManagementClient)
                .getUserDetailsByUsername(TEST_USER_NAME, TEST_ACCOUNT_NAME);

        JwtEncodingContext context = buildInternalIdTokenContext(Set.of(OidcScopes.OPENID, OidcScopes.EMAIL));
        jwtCustomizer.customize(context);

        Map<String, Object> claims = context.getClaims().build().getClaims();
        assertEquals("ada@example.com", claims.get(StandardClaimNames.EMAIL));
        assertNull(claims.get(StandardClaimNames.GIVEN_NAME));
        assertNull(claims.get(StandardClaimNames.PHONE_NUMBER));
        assertNull(claims.get(StandardClaimNames.ADDRESS));
    }

    /**
     * Regression test: {@code addClaimsForIdToken} must not throw when {@code userDetailsResponse} is
     * {@code null} (e.g. a federated IdP configured with a {@code token-info-source} other than
     * {@code FETCH_INTERNAL_USER}) - user-derived claims (user id, username, first/last name) are simply
     * skipped, but the {@code jti} claim is still added.
     */
    @Test
    void jwtTokenCustomizerForIdTokenType_NullUserDetailsResponse_DoesNotThrow() {
        lenient().when(tenantConfigurationService.getTenantProperties()).thenReturn(createMockTenantProperties());
        doReturn(null).when(userManagementClient).getUserDetailsByUsername(TEST_USER_NAME, TEST_ACCOUNT_NAME);

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(new OAuth2TokenType("id_token"))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).build();

        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
        org.junit.jupiter.api.Assertions.assertNotNull(context.getClaims().build().getClaim("jti"));
    }

    /**
     * Verifies that configured ID-token claims are read from UIDAM rather than raw external-IdP
     * attributes for a federated login.
     */
    @Test
    void jwtTokenCustomizerForFederatedIdTokenType_UsesConfiguredUidamClaims() {
        TenantProperties tenantProperties = createMockTenantProperties();
        IdTokenProperties idTokenProperties = new IdTokenProperties();
        idTokenProperties.setAdditionalClaims("email,profile,iss");
        tenantProperties.getClient().setIdTokenProperties(idTokenProperties);
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        attributes.put("email", "external-user@example.com");
        attributes.put("name", "External User");
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        final OAuth2AuthenticationToken principal =
                new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);
        UserDetailsResponse uidamUser = getUser();
        uidamUser.setEmail("uidam-user@example.com");
        uidamUser.getAdditionalAttributes().put("profile", "standard");
        doReturn(uidamUser).when(userManagementClient)
                .getUserDetailsByUsername("google" + "_" + TEST_USER_NAME, null);

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(new OAuth2TokenType("id_token"))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).build();

        jwtCustomizer.customize(context);

        assertEquals("123", context.getClaims().build().getSubject());
        assertEquals("uidam-user@example.com", context.getClaims().build().getClaim("email"));
        assertEquals("standard", context.getClaims().build().getClaim("profile"));
        assertEquals("https://provider.com", context.getClaims().build().getClaim("iss").toString());
        org.junit.jupiter.api.Assertions.assertNotNull(context.getClaims().build().getClaim("jti"));
        assertNull(context.getClaims().build().getClaim("name"));
        verify(userManagementClient).getUserDetailsByUsername("google" + "_" + TEST_USER_NAME, null);
    }

    @Test
    void jwtTokenCustomizerIncludesExternalIdpIdTokenWhenProviderFlagIsEnabled() {
        TenantProperties tenantProperties = createMockTenantProperties();
        tenantProperties.getExternalIdpRegisteredClientList().get(0)
                .setIncludeIdpIdToken(true);
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();
        doReturn(getUser()).when(userManagementClient)
                .getUserDetailsByUsername("google" + "_" + TEST_USER_NAME, null);
        JwtEncodingContext context = buildFederatedIdTokenContext("external-idp-id-token-value");

        jwtCustomizer.customize(context);

        assertEquals("external-idp-id-token-value",
                context.getClaims().build().getClaim(CLAIM_EXTERNAL_IDP_ID_TOKEN));
    }

    @Test
    void jwtTokenCustomizerOmitsExternalIdpIdTokenWhenProviderFlagIsDisabled() {
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        doReturn(getUser()).when(userManagementClient)
                .getUserDetailsByUsername("google" + "_" + TEST_USER_NAME, null);
        JwtEncodingContext context = buildFederatedIdTokenContext("external-idp-id-token-value");

        jwtCustomizer.customize(context);

        assertNull(context.getClaims().build().getClaim(CLAIM_EXTERNAL_IDP_ID_TOKEN));
    }

    /**
     * This test method tests the scenario where the token customization for client
     * credentials grant access token type with scope is successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setAccountType("Root");
        clientCacheDetails.setAccountName("ignite");
        clientCacheDetails.setAccountId("456");
        clientCacheDetails.setTenantId("789");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
                clientPrincipal, null, null);
        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSetWithScope())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for client
     * credentials grant access token type is successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType2() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
                clientPrincipal, null, null);
        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for client
     * credentials grant access token type with multi-role client is successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType3() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
                clientPrincipal, null, null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for client
     * credentials grant access token type with multi-role client and scope is
     * successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType4() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
                clientPrincipal, null, null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSetWithScope())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for client
     * credentials grant access token type with multi-role client and custom scope
     * is successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType5() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
                clientPrincipal, null, null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSetWithCustomScope())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for client credentials grant access token type
     * with empty scope and multi-role client is successful.
     */
    @Test
    void jwtTokenCustomizerForClientCredsGrantAccessTokenType6() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        clientCacheDetails.setClientType("multi_role");
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
            ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2ClientCredentialsAuthenticationToken authorizationGrant = new OAuth2ClientCredentialsAuthenticationToken(
            clientPrincipal, null, null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
            .registeredClient(registeredClient)
            .principal(clientPrincipal)
            .authorization(authorization)
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrant(authorizationGrant)
            .put("custom-key-1", "custom-value-1")
            .context(ctx -> ctx.put("custom-key-2", "custom-value-2"))
            .build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /* This test method tests the scenario where the token customization for refresh
     * grant access token type is successful.
     */
    @Test
    void jwtTokenCustomizerForRefreshGrantAccessTokenType() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * This test method tests the scenario where the token customization for
     * external IDP is successful.
     */
    @Test
    void jwtTokenCustomizerForExternalIdp() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), any());

        RegisteredClient registeredClient = registeredClient().build();
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken principal = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).put("custom-key-1", "custom-value-1")
                .context(ctx -> ctx.put("custom-key-2", "custom-value-2")).build();
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    @Test
    void getUserDetailsForFederatedUser_Success() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        // Setup
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);

        doReturn(getUser()).when(userManagementClient)
                .getUserDetailsByUsername("google" + "_" + TEST_USER_NAME, null);

        // Execute & Verify
        assertDoesNotThrow(() -> jwtCustomizer.customize(createTestContext(token)));
    }

    @Test
    void getUserDetailsForFederatedUser_scopeRoleMappingEnabled_invokesApplyScopeRoleMapping() {
        // Arrange - enable scopeRoleMappings on the google IDP client
        TenantProperties tenantProperties = createMockTenantProperties();
        ExternalIdpRegisteredClient googleClient = tenantProperties.getExternalIdpRegisteredClientList().get(0);
        ScopeRoleMapping rule = new ScopeRoleMapping();
        rule.setExternalRoles("VWAG_STORE_PRE_GROUP_DEV");
        rule.setInternalScopes("IgniteStoreSeller");
        googleClient.setScopePreference(ScopePreference.EXTERNAL);
        googleClient.setScopeRoleMappings(List.of(rule));
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        attributes.put("groups", "VWAG_STORE_PRE_GROUP_DEV");
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);

        doReturn(getUser()).when(userManagementClient)
                .getUserDetailsByUsername("google" + "_" + TEST_USER_NAME, null);

        // Execute
        assertDoesNotThrow(() -> jwtCustomizer.customize(createTestContext(token)));

        // Verify - ClaimsConfigManager delegates to the scope-role mapping service on every federated login
        verify(scopeRoleClaimMappingService).applyScopeRoleMapping(eq(googleClient), eq(attributes),
                any(), any(UserDetailsResponse.class));
    }

    @Test
    void getUserDetailsForFederatedUser_scopeRoleMappingThrowsInvalidScope_propagatesException() {
        // Arrange - simulate the scope-role mapping service rejecting an unmatched EXTERNAL/BOTH rule
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();

        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);

        doReturn(getUser()).when(userManagementClient)
                .getUserDetailsByUsername("google" + "_" + TEST_USER_NAME, null);

        OAuth2AuthenticationException invalidScope = new OAuth2AuthenticationException(
                new OAuth2Error(CustomOauth2TokenGenErrorCodes.INVALID_SCOPE.name()));
        doThrow(invalidScope).when(scopeRoleClaimMappingService)
                .applyScopeRoleMapping(any(), any(), any(), any());

        // Execute & Verify - the exception must propagate, not be swallowed
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> jwtCustomizer.customize(createTestContext(token)));
        assertEquals(CustomOauth2TokenGenErrorCodes.INVALID_SCOPE.name(), exception.getError().getErrorCode());
    }

    @Test
    void getUserDetailsForFederatedUser_CreateNewUser() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        // Setup
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);

        OAuth2AuthenticationException userNotFound = new OAuth2AuthenticationException(
                new OAuth2Error(CustomOauth2TokenGenErrorCodes.USER_NOT_FOUND.name()));

        doThrow(userNotFound).doReturn(getUser()).when(userManagementClient)
                .getUserDetailsByUsername("google" + "_" + TEST_USER_NAME, null);

        doReturn(true).when(claimMappingService).validateClaimCondition(eq("google"), any());

        doReturn(new FederatedUserDto()).when(claimMappingService).mapClaimsToUserRequest(eq("google"),
                any(), any());
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);
        doReturn(getUser()).when(userManagementClient).createFedratedUser(any());

        // Execute & Verify
        assertDoesNotThrow(() -> jwtCustomizer.customize(createTestContext(token)));
    }

    @Test
    void getUserDetailsForFederatedUser_ClaimValidationFails() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        // Setup
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);

        OAuth2AuthenticationException userNotFound = new OAuth2AuthenticationException(
                new OAuth2Error(CustomOauth2TokenGenErrorCodes.USER_NOT_FOUND.name()));

        doThrow(userNotFound).when(userManagementClient)
                .getUserDetailsByUsername("google" + "_" + TEST_USER_NAME, null);

        doReturn(false).when(claimMappingService).validateClaimCondition(eq("google"), any());

        // Execute & Verify
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> customizeToken(token));

        assertEquals("invalid_claim_validation", exception.getError().getErrorCode());
        assertEquals("Claim validation failed for registrationId: google",
                exception.getError().getDescription());
    }

    @Test
    void getUserDetailsForFederatedUser_InvalidIdpConfiguration() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();

        // Setup - use properly formatted registration ID with invalid provider
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, "demo-invalid_idp");

        // Execute & Verify
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> customizeToken(token));

        assertEquals("invalid_idp_configuration", exception.getError().getErrorCode());
        assertEquals("No external IDP configuration found for: demo-invalid_idp",
                exception.getError().getDescription());
    }

    
    @Test
    void findExternalIdpClient_InvalidRegistrationId_ThrowsException() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();
        
        // Setup - use properly formatted registration ID but with invalid provider that doesn't exist in tenant config
        String invalidRegistrationId = "demo-invalidprovider";  // Valid format, but "invalidprovider" doesn't exist
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, invalidRegistrationId);

        // Execute & Verify
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> customizeToken(token));

        assertEquals("invalid_idp_configuration", exception.getError().getErrorCode());
        assertEquals("No external IDP configuration found for: " + invalidRegistrationId, 
                exception.getError().getDescription());
    }

    @Test
    void getUserDetailsForFederatedUser_InvalidRegistrationFormat() {
        // Mock tenant properties
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();

        // Setup - use improperly formatted registration ID (missing tenant prefix)
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, "google"); 

        // Execute & Verify
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> customizeToken(token));

        assertEquals("invalid_registration_format", exception.getError().getErrorCode());
        assertEquals("Registration ID must be in format 'tenant-provider' but was: google",
                exception.getError().getDescription());
    }

    private void customizeToken(OAuth2AuthenticationToken token) {
        jwtCustomizer.customize(createTestContext(token));
    }

    private JwtEncodingContext createTestContext(OAuth2AuthenticationToken principal) {
        RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        return JwtEncodingContext.with(jwsHeader(), jwtClaimsSet()).registeredClient(registeredClient)
                .principal(principal).authorization(authorization).tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).build();
    }

    @Test
    void throwInvalidTenantAccessException_whenTenantPrefixMismatch_shouldThrow() {
        // Arrange - registration ID with wrong tenant prefix "other-google" while current tenant is "demo"
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();

        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        // "other-google" -> tenant prefix "other" != current tenant "demo"
        OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(oauth2User, null, "other-google");

        // Execute & Verify - should throw invalid_tenant_access
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> customizeToken(token));

        assertEquals("invalid_tenant_access", exception.getError().getErrorCode());
    }

    @Test
    void logTokenRefreshed_withOauth2AuthenticationToken_shouldNotThrow() {
        // Arrange - Refresh token with OAuth2 principal (external IdP user)
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), any());

        RegisteredClient registeredClient = registeredClient().build();
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(ATTRIBUTE_SUB, TEST_USER_NAME);
        OAuth2User oauth2User = new DefaultOAuth2User(null, attributes, ATTRIBUTE_SUB);
        OAuth2AuthenticationToken principal = new OAuth2AuthenticationToken(oauth2User, null, REGISTRATION_ID_GOOGLE);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        // Use REFRESH_TOKEN grant type with OAuth2AuthenticationToken principal
        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrant(authorizationGrant).build();

        // Act & Assert
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    @Test
    void getCurrentTenantProperties_whenTenantPropertiesIsNull_shouldThrowIllegalState() {
        // Arrange - tenantConfigurationService returns null
        doReturn(null).when(tenantConfigurationService).getTenantProperties();

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).build();

        // Assert - IllegalStateException when tenant properties are null
        assertThrows(IllegalStateException.class, () -> jwtCustomizer.customize(context));
    }

    @Test
    void populateUserScopes_whenScopelessAndUserHasScopes_shouldMergeScopes() {
        // Arrange - authCodeScopelessUserScopes = true, empty scope request, user has scopes
        TenantProperties tenantProperties = createMockTenantProperties();
        tenantProperties.getClient().setAuthCodeScopelessUserScopes(true);
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        // Return user with scopes
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        // Use jwtClaimsSet() which has empty scope
        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).build();

        // Act & Assert - should not throw
        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    @BeforeEach
    void setUp() {
        jwtCustomizer = claimsConfigManager.jwtTokenCustomizer(cacheClientUtils);
    }

    /**
     * Covers {@code addTenantLevelAdditionalClaims}: the tenant-level allow-list
     * ({@code user.jwt-additional-claim-attributes}) picks a matching key out of
     * {@code additionalAttributes} and adds it as a claim.
     */
    @Test
    void jwtTokenCustomizerAppliesTenantLevelAdditionalClaims() {
        TenantProperties tenantProperties = createMockTenantProperties();
        tenantProperties.getUser().setJwtAdditionalClaimAttributes("firstName");
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        JwtEncodingContext context = buildAuthCodeAccessTokenContext();
        jwtCustomizer.customize(context);

        assertEquals("first", context.getClaims().build().getClaim("firstName"));
    }

    /**
     * Covers {@code applyClientConfig}'s early return when {@code customAttributesForClaims}
     * is blank for an otherwise-matched signup client config.
     */
    @Test
    void applyClientConfigSkipsWhenCustomAttributesForClaimsBlank() {
        TenantProperties tenantProperties = createMockTenantProperties();
        SignupClientConfig signupClientConfig = new SignupClientConfig();
        signupClientConfig.setClientId("client-1");
        tenantProperties.setSignupConfigList(List.of(signupClientConfig));
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        assertDoesNotThrow(() -> jwtCustomizer.customize(buildAuthCodeAccessTokenContext()));
    }

    /**
     * Covers every case of {@code resolveMandatoryFieldClaim}'s switch (including the
     * default/unrecognised branch) plus both the custom-attribute and mandatory-field
     * "missing value" logging branches in {@code applyClientConfig}/{@code logMissingClaimValue}.
     */
    @Test
    void applyClientConfigCoversMandatoryFieldsAndMissingKeys() {
        TenantProperties tenantProperties = createMockTenantProperties();
        SignupClientConfig signupClientConfig = new SignupClientConfig();
        signupClientConfig.setClientId("client-1");
        signupClientConfig.setCustomAttributesForClaims(
                "id,email,accountId,status,tenantId,lastSuccessfulLoginTime,mfaRequired,"
                        + "unknownField,ATTR_firstName,ATTR_missingAttr");
        tenantProperties.setSignupConfigList(List.of(signupClientConfig));
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        assertDoesNotThrow(() -> jwtCustomizer.customize(buildAuthCodeAccessTokenContext()));
    }

    /**
     * Covers the {@code catch (Exception ex)} block in {@code applyClientConfig}: a
     * lookup failure for one claim key must be logged and must not fail token issuance.
     */
    @Test
    void applyClientConfigCatchesExceptionFromCustomAttributeLookup() {
        TenantProperties tenantProperties = createMockTenantProperties();
        SignupClientConfig signupClientConfig = new SignupClientConfig();
        signupClientConfig.setClientId("client-1");
        signupClientConfig.setCustomAttributesForClaims("ATTR_dummy");
        tenantProperties.setSignupConfigList(List.of(signupClientConfig));
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        UserDetailsResponse userDetailsResponse = getUser();
        Map<String, Object> throwingMap = new HashMap<>() {
            @Override
            public Object get(Object key) {
                throw new RuntimeException("boom");
            }
        };
        throwingMap.put("dummy", "value");
        userDetailsResponse.setAdditionalAttributes(throwingMap);
        doReturn(userDetailsResponse).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        assertDoesNotThrow(() -> jwtCustomizer.customize(buildAuthCodeAccessTokenContext()));
    }

    /**
     * Covers the final {@code else} branch of {@code addScopeAndScopes}: when scope/scopes
     * bifurcation is required (tenant-level customization enabled) but {@code clientDetails}
     * is null, a warning is logged and no scope claims are added.
     */
    @Test
    void addScopeAndScopesWarnsWhenClientDetailsNullAndBifurcationRequired() {
        TenantProperties tenantProperties = createMockTenantProperties();
        tenantProperties.getClient().setOauthScopeCustomization(true);
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        doReturn(null).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        assertDoesNotThrow(() -> jwtCustomizer.customize(buildAuthCodeAccessTokenContext()));
    }

    /**
     * Covers {@code addScopeAndScopesForNotClientCredsGrantType}'s multi-role, non-federated
     * path: requested scope is empty and client scopes are non-empty, so the effective scope
     * set falls back to the client's full registered scope list, while the "scopes" claim
     * still reflects the user's own resolved scopes.
     */
    @Test
    void addScopeAndScopesForNotClientCreds_EmptyRequestedScope_FallsBackToClientScopes() {
        TenantProperties tenantProperties = createMockTenantProperties();
        tenantProperties.getClient().setOauthScopeCustomization(true);
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        JwtEncodingContext context = buildAuthCodeAccessTokenContext();
        jwtCustomizer.customize(context);

        assertEquals("SelfManage", context.getClaims().build().getClaim("scope"));
        assertEquals(Set.of("SelfManage", "SelfUserManage"), context.getClaims().build().getClaim("scopes"));
    }

    /**
     * Covers {@code logEmptyClientScopes}: when the client has no registered scopes at all,
     * no "scope"/"scopes" claims are added regardless of the requested scope.
     */
    @Test
    void addScopeAndScopesForNotClientCreds_EmptyClientScopes_NoScopeClaimsAdded() {
        TenantProperties tenantProperties = createMockTenantProperties();
        tenantProperties.getClient().setOauthScopeCustomization(true);
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClientWithEmptyScope().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUser()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        JwtEncodingContext context = buildAuthCodeAccessTokenContext();
        jwtCustomizer.customize(context);

        assertNull(context.getClaims().build().getClaim("scope"));
        assertNull(context.getClaims().build().getClaim("scopes"));
    }

    /**
     * Covers {@code applyNotClientCredsScopeClaims}'s "user scopes empty" branch: only the
     * "scope" claim (client's fallback scope list) is added, with no "scopes" claim.
     */
    @Test
    void addScopeAndScopesForNotClientCreds_EmptyUserScopes_OnlyScopeClaimAdded() {
        TenantProperties tenantProperties = createMockTenantProperties();
        tenantProperties.getClient().setOauthScopeCustomization(true);
        doReturn(tenantProperties).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());
        doReturn(getUserWithEmptyScope()).when(userManagementClient).getUserDetailsByUsername(anyString(), anyString());

        JwtEncodingContext context = buildAuthCodeAccessTokenContext();
        jwtCustomizer.customize(context);

        assertEquals("SelfManage", context.getClaims().build().getClaim("scope"));
        assertNull(context.getClaims().build().getClaim("scopes"));
    }

    /**
     * Covers the "unexpected principal type" branch in {@code logAccessTokenGenerated}.
     * Uses a grant type that {@code addClaimsForAccessToken} does not explicitly handle
     * (so no user/client claims are populated and no NPE occurs on a null user details
     * response) while still not being {@code refresh_token}, so processing falls through
     * to {@code logAccessTokenGenerated} with a principal that is neither a password nor
     * an external-IdP authentication token.
     */
    @Test
    void logAccessTokenGeneratedWarnsOnUnexpectedPrincipalType() {
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        // Principal is neither CustomUserPwdAuthenticationToken nor OAuth2AuthenticationToken.
        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(new AuthorizationGrantType("custom_grant"))
                .authorizationGrant(authorizationGrant).build();

        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * Covers the "unexpected principal type" branch in {@code logTokenRefreshed}
     * (refresh_token grant with a principal that is neither a password nor an
     * external-IdP authentication token).
     */
    @Test
    void logTokenRefreshedWarnsOnUnexpectedPrincipalType() {
        doReturn(createMockTenantProperties()).when(tenantConfigurationService).getTenantProperties();

        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient().build());
        doReturn(clientCacheDetails).when(cacheClientUtils).getClientDetails(anyString());

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        JwtEncodingContext context = JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(clientPrincipal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrant(authorizationGrant).build();

        assertDoesNotThrow(() -> jwtCustomizer.customize(context));
    }

    /**
     * Covers the {@code accessTokenCustomizer} bean for opaque access tokens.
     */
    @Test
    void accessTokenCustomizerCustomizesAccessTokenType() {
        OAuth2TokenCustomizer<org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext>
                customizer = claimsConfigManager.accessTokenCustomizer();
        org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext context =
                org.mockito.Mockito.mock(
                    org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext.class);
        doReturn(OAuth2TokenType.ACCESS_TOKEN).when(context).getTokenType();

        assertDoesNotThrow(() -> customizer.customize(context));
    }

    /**
     * Covers the {@code accessTokenCustomizer} bean for opaque refresh tokens.
     */
    @Test
    void accessTokenCustomizerCustomizesRefreshTokenType() {
        OAuth2TokenCustomizer<org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext>
                customizer = claimsConfigManager.accessTokenCustomizer();
        org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext context =
                org.mockito.Mockito.mock(
                    org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext.class);
        doReturn(OAuth2TokenType.REFRESH_TOKEN).when(context).getTokenType();

        assertDoesNotThrow(() -> customizer.customize(context));
    }

    /**
     * Builds a minimal authorization_code / access_token {@link JwtEncodingContext} using a
     * password-authenticated principal for client {@code client-1}.
     */
    private JwtEncodingContext buildAuthCodeAccessTokenContext() {
        RegisteredClient registeredClient = registeredClient().build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(TEST_USER_NAME, TEST_PASSWORD,
                TEST_ACCOUNT_NAME, null);
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        return JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).build();
    }

    /**
     * Builds an authorization-code ID-token context with an upstream OIDC ID token.
     *
     * @param tokenValue raw external provider ID-token value
     * @return federated ID-token encoding context
     */
    private JwtEncodingContext buildFederatedIdTokenContext(String tokenValue) {
        Instant issuedAt = Instant.now();
        OidcIdToken externalIdpIdToken = OidcIdToken.withTokenValue(tokenValue)
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plusSeconds(EXTERNAL_IDP_ID_TOKEN_TTL_SECONDS))
                .subject(TEST_USER_NAME)
                .build();
        DefaultOidcUser oidcUser = new DefaultOidcUser(
                List.of(new SimpleGrantedAuthority("ROLE_USER")), externalIdpIdToken);
        OAuth2AuthenticationToken principal = new OAuth2AuthenticationToken(
                oidcUser, oidcUser.getAuthorities(), REGISTRATION_ID_GOOGLE);

        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        return JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient).principal(principal).authorization(authorization)
                .tokenType(new OAuth2TokenType("id_token"))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant).build();
    }

    private JwtEncodingContext buildInternalIdTokenContext(Set<String> authorizedScopes) {
        RegisteredClient registeredClient = registeredClient().build();
        OAuth2Authorization authorization = TestOauth2Authorizations.authorization(registeredClient).build();
        CustomUserPwdAuthenticationToken principal = new CustomUserPwdAuthenticationToken(
                TEST_USER_NAME, TEST_PASSWORD, TEST_ACCOUNT_NAME, null);
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
        OAuth2AuthorizationRequest authorizationRequest = authorization
                .getAttribute(OAuth2AuthorizationRequest.class.getName());
        OAuth2AuthorizationCodeAuthenticationToken authorizationGrant = new OAuth2AuthorizationCodeAuthenticationToken(
                "code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

        return JwtEncodingContext.with(jwsHeader(), jwtClaimsSet())
                .registeredClient(registeredClient)
                .principal(principal)
                .authorization(authorization)
                .authorizedScopes(authorizedScopes)
                .tokenType(new OAuth2TokenType("id_token"))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationGrant)
                .build();
    }

    /**
     * Helper method to create mock tenant properties for testing.
     */
    private TenantProperties createMockTenantProperties() {
        TenantProperties tenantProperties = new TenantProperties();
        tenantProperties.setTenantId("demo");  // Updated to match registration ID format "demo-google"
        
        // Set up account properties
        AccountProperties accountProperties = new AccountProperties();
        accountProperties.setAccountType("Root");
        accountProperties.setAccountName("ignite");
        accountProperties.setAccountId("456");
        tenantProperties.setAccount(accountProperties);
        
        // Set up client properties
        ClientProperties clientProperties = new ClientProperties();
        tenantProperties.setClient(clientProperties);
        
        // Set up user properties
        UserProperties userProperties = new UserProperties();
        tenantProperties.setUser(userProperties);
        
        // Set up external IDP configurations for the tests
        tenantProperties.setExternalIdpEnabled(true);
        tenantProperties.setExternalIdpClientName("federated-user-client");
        
       
        
        ExternalIdpRegisteredClient googleClient = new ExternalIdpRegisteredClient();
        googleClient.setEnabled(true);
        googleClient.setClientName("Google");
        googleClient.setRegistrationId("google");  // Original provider ID, will be prefixed with tenant
        googleClient.setClientId("mock-google-client-id");
        googleClient.setClientSecret("mock-google-client-secret");
        googleClient.setClientAuthenticationMethod("client_secret_basic");
        googleClient.setScope("openid, profile, email");
        googleClient.setAuthorizationUri("https://accounts.google.com/o/oauth2/v2/auth");
        googleClient.setTokenUri("https://www.googleapis.com/oauth2/v4/token");
        googleClient.setUserInfoUri("https://www.googleapis.com/oauth2/v3/userinfo");
        googleClient.setUserNameAttributeName("sub");
        googleClient.setJwkSetUri("https://www.googleapis.com/oauth2/v3/certs");
        googleClient.setTokenInfoSource("FETCH_INTERNAL_USER");
        googleClient.setCreateUserMode("CREATE_INTERNAL_USER");
        googleClient.setDefaultUserRoles(Set.of("VEHICLE_OWNER"));
        googleClient.setClaimMappings("firstName#given_name,lastName#family_name,email#email");
        // Create external IDP registered client list for Google
        java.util.List<ExternalIdpRegisteredClient> externalIdpList =
                new java.util.ArrayList<>();
        externalIdpList.add(googleClient);
        tenantProperties.setExternalIdpRegisteredClientList(externalIdpList);
        
        return tenantProperties;
    }
}
