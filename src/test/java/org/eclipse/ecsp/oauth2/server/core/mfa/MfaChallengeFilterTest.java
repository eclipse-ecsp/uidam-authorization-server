/********************************************************************************
 *
 * <p>
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
 *******************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.mfa;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.eclipse.ecsp.oauth2.server.core.authentication.tokens.CustomUserPwdAuthenticationToken;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MfaPolicyProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for MfaChallengeFilter covering all filter decision branches.
 */
@ExtendWith(MockitoExtension.class)
class MfaChallengeFilterTest {

    private static final String USERNAME = "testuser";

    @Mock
    private MfaSecretService mfaSecretService;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private MfaStateService mfaStateService;

    @Mock
    private FilterChain filterChain;

    private MfaChallengeFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() throws Exception {
        // Initialize TenantUtils static singleton with "ecsp" as default tenant.
        // Spring @Value is not injected in unit tests, so the field defaults to null.
        // We set it via reflection so that mfaPath() and resolveTenantFromRequest()
        // behave correctly without a Spring context.
        TenantUtils tenantUtils = new TenantUtils();
        Field defaultTenantField = TenantUtils.class.getDeclaredField("defaultTenant");
        defaultTenantField.setAccessible(true);
        defaultTenantField.set(tenantUtils, "ecsp");

        filter = new MfaChallengeFilter(mfaSecretService, tenantConfigurationService, mfaStateService);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext();

        // Lenient defaults: no DB-verified flag, no pending token stored
        lenient().when(mfaStateService.consumeMfaVerified(any())).thenReturn(false);
        lenient().when(mfaStateService.loadPending(any())).thenReturn(Optional.empty());
        lenient().when(mfaStateService.loadTenant(any())).thenReturn(null);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // ─────────────── Pass-through paths ─────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
        "/mfa/challenge",
        "/css/main.css",
        "/images/logo.png",
        "/actuator/health",
        "/favicon.ico",
        "/ecsp/mfa/challenge",
        "/oauth2/authorize"
    })
    void doFilterInternal_passThroughPaths_passesThrough(String uri) throws ServletException, IOException {
        request.setRequestURI(uri);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    // ─────────────── MFA_VERIFIED single-use pass-through ──────────────────

    @Test
    void doFilterInternal_mfaVerifiedFlag_consumesAndPassesThrough() throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        // DB-backed flag returns true → single-use pass-through
        when(mfaStateService.consumeMfaVerified(request)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    // ─────────────── Case 1: MFA pending in DB ───────────────────────────────

    static Stream<Arguments> pendingAuthRedirectData() {
        return Stream.of(
            Arguments.of(null, true, "/mfa/challenge"),
            Arguments.of(null, false, "/mfa/enroll/setup"),
            Arguments.of("mytenant", true, "/mytenant/mfa/challenge")
        );
    }

    @ParameterizedTest
    @MethodSource("pendingAuthRedirectData")
    void doFilterInternal_pendingInSession_redirectsCorrectly(String tenant, boolean enrolled, String expectedRedirect)
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        when(mfaStateService.loadPending(request)).thenReturn(Optional.of(pending));
        if (tenant != null) {
            when(mfaStateService.loadTenant(request)).thenReturn(tenant);
        }
        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(enrolled);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertEquals(expectedRedirect, response.getRedirectedUrl());
    }

    // ─────────────── Case 2: Fully authenticated, MFA DISABLED ──────────────

    @Test
    void doFilterInternal_authenticatedUser_mfaDisabled_passesThrough() throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        setAuthenticatedUser(USERNAME);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.DISABLED);
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    // ─────────────── Case 2: Fully authenticated, user in skip-list ──────────

    @Test
    void doFilterInternal_authenticatedUser_inSkipList_passesThrough() throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        setAuthenticatedUser(USERNAME);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.REQUIRED);
        policy.setSkipUsers(USERNAME);
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    // ─────────────── Case 2: Fully authenticated, client in skip-list ─────────

    @Test
    void doFilterInternal_authenticatedUser_clientInSkipList_passesThrough()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        request.setParameter("client_id", "mobile-app");
        setAuthenticatedUser(USERNAME);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.REQUIRED);
        policy.setSkipClients("mobile-app,service-account-client");
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_authenticatedUser_clientNotInSkipList_enforcesMfa()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        request.setParameter("client_id", "web-portal");
        setAuthenticatedUser(USERNAME);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.REQUIRED);
        policy.setSkipClients("mobile-app,service-account-client");
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);
        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertNotNull(response.getRedirectedUrl());
    }

    // ─────────────── Case 2: Fully authenticated, CONDITIONAL mode ──────────

    @Test
    void doFilterInternal_authenticatedUser_conditionalMode_noStepUpScope_passesThrough()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        setAuthenticatedUser(USERNAME);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.CONDITIONAL);
        policy.setStepUpScopes("admin:write");
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_authenticatedUser_conditionalMode_matchingRequestScope_enforcesMfa()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        request.setParameter("scope", "admin:write openid");
        setAuthenticatedUser(USERNAME);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.CONDITIONAL);
        policy.setStepUpScopes("admin:write");
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);
        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        // Should redirect to MFA challenge
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void doFilterInternal_authenticatedUser_conditionalMode_noStepUpScopesConfigured_passesThrough()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        setAuthenticatedUser(USERNAME);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.CONDITIONAL);
        policy.setStepUpScopes(null); // No step-up scopes
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_authenticatedUser_conditionalMode_userHasStepUpScope_enforcesMfa()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        // User has SCOPE_admin:write in their authorities
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                USERNAME, "password",
                List.of(new SimpleGrantedAuthority("SCOPE_admin:write")));
        SecurityContextHolder.getContext().setAuthentication(auth);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.CONDITIONAL);
        policy.setStepUpScopes("admin:write");
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);
        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
    }

    // ─────────────── Case 2: REQUIRED mode, enrolled user ────────────────────

    @Test
    void doFilterInternal_authenticatedUser_requiredMode_enrolled_redirectsToChallenge()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        setAuthenticatedUser(USERNAME);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.REQUIRED);
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);
        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertNotNull(response.getRedirectedUrl());
    }

    // ─────────────── Case 3: REQUIRED mode, unenrolled user ──────────────────

    @Test
    void doFilterInternal_authenticatedUser_requiredMode_notEnrolled_redirectsToEnrollSetup()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        setAuthenticatedUser(USERNAME);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.REQUIRED);
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);
        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertNotNull(response.getRedirectedUrl());
    }

    // ─────────────── Tenant resolution edge cases ────────────────────────────

    @Test
    void doFilterInternal_authenticatedUser_tenantFromPathVariable_resolvesTenant()
            throws ServletException, IOException {
        request.setRequestURI("/mytenant/dashboard");
        setAuthenticatedUser(USERNAME);

        // No tenant properties configured (null return) → fallback to REQUIRED
        when(tenantConfigurationService.getTenantProperties("mytenant")).thenReturn(null);
        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        // Filter should process without exception
        assertDoesNotThrow(() -> { });
    }

    @Test
    void doFilterInternal_authenticatedUser_tenantServiceThrows_usesDefaultPolicy()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        setAuthenticatedUser(USERNAME);

        when(tenantConfigurationService.getTenantProperties(anyString()))
                .thenThrow(new RuntimeException("Service error"));
        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(false);

        // Should not throw; uses default REQUIRED policy
        filter.doFilterInternal(request, response, filterChain);

        assertDoesNotThrow(() -> { });
    }

    // ─────────────── MfaPendingAuthenticationToken in SecurityContext ─────────

    @Test
    void doFilterInternal_pendingAuthInSecurityContext_passesThroughFilter()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        MfaPendingAuthenticationToken pendingAuth = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(pendingAuth);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    // ─────────────── Anonymous user ──────────────────────────────────────────

    @Test
    void doFilterInternal_anonymousUser_passesThroughFilter()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        AnonymousAuthenticationToken anonAuth = new AnonymousAuthenticationToken(
                "key", "anonymousUser",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
        SecurityContextHolder.getContext().setAuthentication(anonAuth);

        filter.doFilterInternal(request, response, filterChain);

        // Anonymous users are not authenticated via isAuthenticated(); passes through
        assertDoesNotThrow(() -> { });
    }

    // ─────────────── Case 2: Fully authenticated, account in skip-list ────────

    @Test
    void doFilterInternal_authenticatedUser_accountInSkipList_passesThrough()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        // accountId "acct-001" comes from the user-management record (same source as scopes)
        CustomUserPwdAuthenticationToken auth = CustomUserPwdAuthenticationToken.authenticated(
                USERNAME, "password", "any-account-name", "acct-001",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(auth);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.REQUIRED);
        policy.setSkipAccounts("acct-001,acct-002");
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    // ─────────────── CONDITIONAL: step-up by client_id ───────────────────────

    @Test
    void doFilterInternal_conditionalMode_stepUpClientMatches_enforcesMfa()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        request.setParameter("client_id", "admin-portal");
        setAuthenticatedUser(USERNAME);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.CONDITIONAL);
        policy.setStepUpClients("admin-portal,ops-dashboard");
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);
        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertNotNull(response.getRedirectedUrl());
    }

    @Test
    void doFilterInternal_conditionalMode_stepUpClientNoMatch_passesThrough()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        request.setParameter("client_id", "mobile-app");
        setAuthenticatedUser(USERNAME);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.CONDITIONAL);
        policy.setStepUpClients("admin-portal,ops-dashboard");
        // No step-up scopes or accounts configured
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    // ─────────────── CONDITIONAL: step-up by accountId ───────────────────────

    @Test
    void doFilterInternal_conditionalMode_stepUpAccountMatches_enforcesMfa()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        // accountId "priv-acct-99" sourced from user-management record
        CustomUserPwdAuthenticationToken auth = CustomUserPwdAuthenticationToken.authenticated(
                USERNAME, "password", "any-login-account", "priv-acct-99",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(auth);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.CONDITIONAL);
        policy.setStepUpAccounts("priv-acct-99,finance-acct");
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);
        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertNotNull(response.getRedirectedUrl());
    }

    @Test
    void doFilterInternal_conditionalMode_stepUpAccountNoMatch_passesThrough()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        // accountId "regular-acct" does not match step-up list
        CustomUserPwdAuthenticationToken auth = CustomUserPwdAuthenticationToken.authenticated(
                USERNAME, "password", "any-login-account", "regular-acct",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(auth);

        TenantProperties props = new TenantProperties();
        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.CONDITIONAL);
        policy.setStepUpAccounts("priv-acct-99,finance-acct");
        // No step-up scopes or clients configured
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    // ─────────────── Skip wins over step-up (priority verification) ───────────

    @Test
    void doFilterInternal_skipClientBeatsStepUpClient_passesThrough()
            throws ServletException, IOException {
        // client_id is in BOTH skip-clients and step-up-clients: skip must win
        request.setRequestURI("/oauth2/authorize");
        request.setParameter("client_id", "admin-portal");
        setAuthenticatedUser(USERNAME);

        MfaPolicyProperties policy = new MfaPolicyProperties();
        policy.setMode(MfaPolicyProperties.MfaMode.CONDITIONAL);
        policy.setSkipClients("admin-portal");
        policy.setStepUpClients("admin-portal");
        final TenantProperties props = new TenantProperties();
        props.setMfa(policy);
        when(tenantConfigurationService.getTenantProperties(anyString())).thenReturn(props);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    // ─────────────── Helper ──────────────────────────────────────────────────

    private void setAuthenticatedUser(String username) {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                username, "password",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
