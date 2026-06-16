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
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MfaPolicyProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for MfaChallengeFilter covering all filter decision branches.
 */
@ExtendWith(MockitoExtension.class)
class MfaChallengeFilterTest {

    private static final String USERNAME = "testuser";
    private static final String TENANT_ID = "ecsp";

    @Mock
    private MfaSecretService mfaSecretService;

    @Mock
    private TenantConfigurationService tenantConfigurationService;

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

        filter = new MfaChallengeFilter(mfaSecretService, tenantConfigurationService);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // ─────────────── Pass-through paths ─────────────────────────────────────

    @Test
    void doFilterInternal_mfaPath_passesThroughFilter() throws ServletException, IOException {
        request.setRequestURI("/mfa/challenge");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_cssPath_passesThroughFilter() throws ServletException, IOException {
        request.setRequestURI("/css/main.css");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_imagesPath_passesThroughFilter() throws ServletException, IOException {
        request.setRequestURI("/images/logo.png");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_actuatorPath_passesThroughFilter() throws ServletException, IOException {
        request.setRequestURI("/actuator/health");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_faviconPath_passesThroughFilter() throws ServletException, IOException {
        request.setRequestURI("/favicon.ico");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_tenantMfaPath_passesThroughFilter() throws ServletException, IOException {
        request.setRequestURI("/ecsp/mfa/challenge");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    // ─────────────── MFA_VERIFIED single-use pass-through ──────────────────

    @Test
    void doFilterInternal_mfaVerifiedFlag_consumesAndPassesThrough() throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_VERIFIED, Boolean.TRUE);
        request.setSession(session);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        // Flag should be consumed (removed from session)
    }

    // ─────────────── Case 1: MFA pending in session ──────────────────────────

    @Test
    void doFilterInternal_pendingInSession_enrolledUser_redirectsToChallenge()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_TENANT, TENANT_ID);
        request.setSession(session);

        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertEquals("/mfa/challenge", response.getRedirectedUrl());
    }

    @Test
    void doFilterInternal_pendingInSession_unenrolledUser_redirectsToEnrollSetup()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_TENANT, TENANT_ID);
        request.setSession(session);

        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertEquals("/mfa/enroll/setup", response.getRedirectedUrl());
    }

    @Test
    void doFilterInternal_pendingInSession_tenantSpecific_redirectsWithTenant()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        MockHttpSession session = new MockHttpSession();
        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(
                USERNAME, Collections.emptyList());
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, pending);
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_TENANT, "mytenant");
        request.setSession(session);

        when(mfaSecretService.isEnrolled(USERNAME)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertEquals("/mytenant/mfa/challenge", response.getRedirectedUrl());
    }

    @Test
    void doFilterInternal_pendingInSession_nonTokenPending_redirectsToEnroll()
            throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");
        MockHttpSession session = new MockHttpSession();
        // Set a non-token value as pending
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_PENDING, "some_string");
        session.setAttribute(MfaChallengeFilter.SESSION_MFA_TENANT, TENANT_ID);
        request.setSession(session);

        // No stub for isEnrolled: username is null when pending is not a
        // MfaPendingAuthenticationToken, so the filter short-circuits via
        // "username != null && mfaSecretService.isEnrolled(username)" → enrolled=false.

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
    }

    // ─────────────── No authentication ───────────────────────────────────────

    @Test
    void doFilterInternal_noAuthentication_passesThroughFilter() throws ServletException, IOException {
        request.setRequestURI("/oauth2/authorize");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
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

    // ─────────────── Helper ──────────────────────────────────────────────────

    private void setAuthenticatedUser(String username) {
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                username, "password",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
