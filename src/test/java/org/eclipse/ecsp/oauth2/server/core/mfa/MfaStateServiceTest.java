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

import org.eclipse.ecsp.oauth2.server.core.entities.AuthorizationSecurityContext;
import org.eclipse.ecsp.oauth2.server.core.entities.MfaFlowState;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationSecurityContextRepository;
import org.eclipse.ecsp.oauth2.server.core.repositories.MfaFlowStateRepository;
import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.lang.reflect.Field;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link MfaStateService}.
 */
@ExtendWith(MockitoExtension.class)
class MfaStateServiceTest {

    private static final String USERNAME = "testuser";
    private static final String SESSION_ID = "test-session-id";
    private static final String TENANT_ID = "ecsp";

    @Mock
    private AuthorizationSecurityContextRepository securityContextRepo;

    @Mock
    private MfaFlowStateRepository mfaFlowStateRepo;

    private MfaStateService service;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() throws Exception {
        TenantUtils tenantUtils = new TenantUtils();
        Field defaultTenantField = TenantUtils.class.getDeclaredField("defaultTenant");
        defaultTenantField.setAccessible(true);
        defaultTenantField.set(tenantUtils, TENANT_ID);

        service = new MfaStateService(securityContextRepo, mfaFlowStateRepo);
        request = new MockHttpServletRequest();
        request.setSession(new org.springframework.mock.web.MockHttpSession(null, SESSION_ID));
    }

    // ─────────────────────── sessionId ──────────────────────────────────────

    @Test
    void sessionId_returnsSessionIdFromRequest() {
        String sid = service.sessionId(request);
        assertEquals(SESSION_ID, sid);
    }

    // ─────────────────────── savePending ────────────────────────────────────

    @Test
    void savePending_existingContext_updatesAndSaves() {
        AuthorizationSecurityContext existing = buildCtx();
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.of(existing));

        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(USERNAME,
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
        service.savePending(request, pending, TENANT_ID);

        ArgumentCaptor<AuthorizationSecurityContext> captor =
                ArgumentCaptor.forClass(AuthorizationSecurityContext.class);
        verify(securityContextRepo).save(captor.capture());
        AuthorizationSecurityContext saved = captor.getValue();
        assertEquals(USERNAME, saved.getMfaPendingUsername());
        assertEquals("ROLE_USER", saved.getMfaPendingAuthorities());
        assertEquals(TENANT_ID, saved.getMfaTenant());
        assertFalse(saved.getMfaVerifiedOnce());
    }

    @Test
    void savePending_noExistingContext_createsNewAndSaves() {
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.empty());

        MfaPendingAuthenticationToken pending = new MfaPendingAuthenticationToken(USERNAME,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER")));
        service.savePending(request, pending, TENANT_ID);

        ArgumentCaptor<AuthorizationSecurityContext> captor =
                ArgumentCaptor.forClass(AuthorizationSecurityContext.class);
        verify(securityContextRepo).save(captor.capture());
        AuthorizationSecurityContext saved = captor.getValue();
        assertEquals(USERNAME, saved.getMfaPendingUsername());
        assertTrue(saved.getMfaPendingAuthorities().contains("ROLE_ADMIN"));
        assertTrue(saved.getMfaPendingAuthorities().contains("ROLE_USER"));
        assertEquals(TENANT_ID, saved.getMfaTenant());
        assertEquals(SESSION_ID, saved.getSessionId());
    }

    // ─────────────────────── loadPending ────────────────────────────────────

    @Test
    void loadPending_contextWithPendingUsername_returnsToken() {
        AuthorizationSecurityContext ctx = buildCtx();
        ctx.setMfaPendingUsername(USERNAME);
        ctx.setMfaPendingAuthorities("ROLE_USER,ROLE_ADMIN");
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.of(ctx));

        Optional<MfaPendingAuthenticationToken> result = service.loadPending(request);

        assertTrue(result.isPresent());
        assertEquals(USERNAME, result.get().getName());
        assertEquals(2, result.get().getPendingAuthorities().size());
    }

    @Test
    void loadPending_contextWithBlankUsername_returnsEmpty() {
        AuthorizationSecurityContext ctx = buildCtx();
        ctx.setMfaPendingUsername("   ");
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.of(ctx));

        Optional<MfaPendingAuthenticationToken> result = service.loadPending(request);

        assertFalse(result.isPresent());
    }

    @Test
    void loadPending_noContext_returnsEmpty() {
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.empty());

        Optional<MfaPendingAuthenticationToken> result = service.loadPending(request);

        assertFalse(result.isPresent());
    }

    @Test
    void loadPending_contextWithNullAuthorities_returnsTokenWithEmptyAuthorities() {
        AuthorizationSecurityContext ctx = buildCtx();
        ctx.setMfaPendingUsername(USERNAME);
        ctx.setMfaPendingAuthorities(null);
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.of(ctx));

        Optional<MfaPendingAuthenticationToken> result = service.loadPending(request);

        assertTrue(result.isPresent());
        assertTrue(result.get().getPendingAuthorities().isEmpty());
    }

    // ─────────────────────── loadTenant ────────────────────────────────────

    @Test
    void loadTenant_contextWithTenant_returnsTenant() {
        AuthorizationSecurityContext ctx = buildCtx();
        ctx.setMfaTenant("tenant1");
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.of(ctx));

        String tenant = service.loadTenant(request);

        assertEquals("tenant1", tenant);
    }

    @Test
    void loadTenant_noContext_returnsDefaultTenant() {
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.empty());

        String tenant = service.loadTenant(request);

        assertEquals(TENANT_ID, tenant);
    }

    @Test
    void loadTenant_contextWithBlankTenant_returnsDefaultTenant() {
        AuthorizationSecurityContext ctx = buildCtx();
        ctx.setMfaTenant("  ");
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.of(ctx));

        String tenant = service.loadTenant(request);

        assertEquals(TENANT_ID, tenant);
    }

    // ─────────────────────── clearPending ───────────────────────────────────

    @Test
    void clearPending_existingContext_clearsFieldsAndSaves() {
        AuthorizationSecurityContext ctx = buildCtx();
        ctx.setMfaPendingUsername(USERNAME);
        ctx.setMfaPendingAuthorities("ROLE_USER");
        ctx.setMfaTenant(TENANT_ID);
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.of(ctx));

        service.clearPending(request);

        ArgumentCaptor<AuthorizationSecurityContext> captor =
                ArgumentCaptor.forClass(AuthorizationSecurityContext.class);
        verify(securityContextRepo).save(captor.capture());
        AuthorizationSecurityContext saved = captor.getValue();
        assertNull(saved.getMfaPendingUsername());
        assertNull(saved.getMfaPendingAuthorities());
        assertNull(saved.getMfaTenant());
        assertFalse(saved.getMfaVerifiedOnce());
    }

    @Test
    void clearPending_noContext_doesNotSave() {
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.empty());

        service.clearPending(request);

        verify(securityContextRepo, never()).save(any());
    }

    // ─────────────────────── setMfaVerified ─────────────────────────────────

    @Test
    void setMfaVerified_existingContext_setsVerifiedAndSaves() {
        AuthorizationSecurityContext ctx = buildCtx();
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.of(ctx));

        service.setMfaVerified(request);

        ArgumentCaptor<AuthorizationSecurityContext> captor =
                ArgumentCaptor.forClass(AuthorizationSecurityContext.class);
        verify(securityContextRepo).save(captor.capture());
        assertTrue(captor.getValue().getMfaVerifiedOnce());
    }

    @Test
    void setMfaVerified_noExistingContext_createsNewContextWithVerifiedFlag() {
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.empty());

        service.setMfaVerified(request);

        ArgumentCaptor<AuthorizationSecurityContext> captor =
                ArgumentCaptor.forClass(AuthorizationSecurityContext.class);
        verify(securityContextRepo).save(captor.capture());
        AuthorizationSecurityContext saved = captor.getValue();
        assertTrue(saved.getMfaVerifiedOnce());
        assertEquals(SESSION_ID, saved.getSessionId());
    }

    // ─────────────────────── consumeMfaVerified ─────────────────────────────

    @Test
    void consumeMfaVerified_flagTrue_returnsTrueAndResetsFlag() {
        AuthorizationSecurityContext ctx = buildCtx();
        ctx.setMfaVerifiedOnce(Boolean.TRUE);
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.of(ctx));

        boolean result = service.consumeMfaVerified(request);

        assertTrue(result);
        ArgumentCaptor<AuthorizationSecurityContext> captor =
                ArgumentCaptor.forClass(AuthorizationSecurityContext.class);
        verify(securityContextRepo).save(captor.capture());
        assertFalse(captor.getValue().getMfaVerifiedOnce());
    }

    @Test
    void consumeMfaVerified_flagFalse_returnsFalse() {
        AuthorizationSecurityContext ctx = buildCtx();
        ctx.setMfaVerifiedOnce(Boolean.FALSE);
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.of(ctx));

        boolean result = service.consumeMfaVerified(request);

        assertFalse(result);
        verify(securityContextRepo, never()).save(any());
    }

    @Test
    void consumeMfaVerified_noContext_returnsFalse() {
        when(securityContextRepo.findBySessionId(SESSION_ID)).thenReturn(Optional.empty());

        boolean result = service.consumeMfaVerified(request);

        assertFalse(result);
        verify(securityContextRepo, never()).save(any());
    }

    // ─────────────────────── markRecoverySent ───────────────────────────────

    @Test
    void markRecoverySent_existingState_updatesTimestamp() {
        MfaFlowState existing = buildFlowState();
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.of(existing));

        service.markRecoverySent(USERNAME);

        ArgumentCaptor<MfaFlowState> captor = ArgumentCaptor.forClass(MfaFlowState.class);
        verify(mfaFlowStateRepo).save(captor.capture());
        assertNotNull(captor.getValue().getRecoverySentAt());
    }

    @Test
    void markRecoverySent_noExistingState_createsNewAndSaves() {
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.empty());

        service.markRecoverySent(USERNAME);

        ArgumentCaptor<MfaFlowState> captor = ArgumentCaptor.forClass(MfaFlowState.class);
        verify(mfaFlowStateRepo).save(captor.capture());
        MfaFlowState saved = captor.getValue();
        assertEquals(USERNAME, saved.getUsername());
        assertNotNull(saved.getRecoverySentAt());
    }

    // ─────────────────────── getRecoverySentAt ──────────────────────────────

    @Test
    void getRecoverySentAt_stateExists_returnsTimestamp() {
        MfaFlowState state = buildFlowState();
        Timestamp ts = Timestamp.from(Instant.now());
        state.setRecoverySentAt(ts);
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.of(state));

        Long result = service.getRecoverySentAt(USERNAME);

        assertNotNull(result);
        assertEquals(ts.getTime(), result);
    }

    @Test
    void getRecoverySentAt_noState_returnsNull() {
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.empty());

        Long result = service.getRecoverySentAt(USERNAME);

        assertNull(result);
    }

    @Test
    void getRecoverySentAt_stateExistsButTimestampNull_returnsNull() {
        MfaFlowState state = buildFlowState();
        state.setRecoverySentAt(null);
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.of(state));

        Long result = service.getRecoverySentAt(USERNAME);

        assertNull(result);
    }

    // ─────────────────────── markRecoveryEmailVerified ──────────────────────

    @Test
    void markRecoveryEmailVerified_existingState_setsVerifiedTrue() {
        MfaFlowState existing = buildFlowState();
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.of(existing));

        service.markRecoveryEmailVerified(USERNAME);

        ArgumentCaptor<MfaFlowState> captor = ArgumentCaptor.forClass(MfaFlowState.class);
        verify(mfaFlowStateRepo).save(captor.capture());
        assertTrue(captor.getValue().getRecoveryEmailVerified());
    }

    @Test
    void markRecoveryEmailVerified_noExistingState_createsNewAndSetsVerifiedTrue() {
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.empty());

        service.markRecoveryEmailVerified(USERNAME);

        ArgumentCaptor<MfaFlowState> captor = ArgumentCaptor.forClass(MfaFlowState.class);
        verify(mfaFlowStateRepo).save(captor.capture());
        MfaFlowState saved = captor.getValue();
        assertEquals(USERNAME, saved.getUsername());
        assertTrue(saved.getRecoveryEmailVerified());
    }

    // ─────────────────────── isRecoveryEmailVerified ────────────────────────

    @Test
    void isRecoveryEmailVerified_verifiedTrue_returnsTrue() {
        MfaFlowState state = buildFlowState();
        state.setRecoveryEmailVerified(Boolean.TRUE);
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.of(state));

        assertTrue(service.isRecoveryEmailVerified(USERNAME));
    }

    @Test
    void isRecoveryEmailVerified_verifiedFalse_returnsFalse() {
        MfaFlowState state = buildFlowState();
        state.setRecoveryEmailVerified(Boolean.FALSE);
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.of(state));

        assertFalse(service.isRecoveryEmailVerified(USERNAME));
    }

    @Test
    void isRecoveryEmailVerified_noState_returnsFalse() {
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.empty());

        assertFalse(service.isRecoveryEmailVerified(USERNAME));
    }

    // ─────────────────────── clearRecoveryState ─────────────────────────────

    @Test
    void clearRecoveryState_existingState_clearsTimestampAndVerifiedFlag() {
        MfaFlowState state = buildFlowState();
        state.setRecoverySentAt(Timestamp.from(Instant.now()));
        state.setRecoveryEmailVerified(Boolean.TRUE);
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.of(state));

        service.clearRecoveryState(USERNAME);

        ArgumentCaptor<MfaFlowState> captor = ArgumentCaptor.forClass(MfaFlowState.class);
        verify(mfaFlowStateRepo).save(captor.capture());
        MfaFlowState saved = captor.getValue();
        assertNull(saved.getRecoverySentAt());
        assertFalse(saved.getRecoveryEmailVerified());
    }

    @Test
    void clearRecoveryState_noState_doesNotSave() {
        when(mfaFlowStateRepo.findById(USERNAME)).thenReturn(Optional.empty());

        service.clearRecoveryState(USERNAME);

        verify(mfaFlowStateRepo, never()).save(any());
    }

    // ─────────────────────── Helpers ────────────────────────────────────────

    private AuthorizationSecurityContext buildCtx() {
        AuthorizationSecurityContext ctx = new AuthorizationSecurityContext();
        ctx.setSessionId(SESSION_ID);
        ctx.setPrincipal("mfa-pending");
        ctx.setAuthenticated(Boolean.FALSE);
        Timestamp now = Timestamp.from(Instant.now());
        ctx.setCreatedDate(now);
        ctx.setUpdatedDate(now);
        return ctx;
    }

    private MfaFlowState buildFlowState() {
        MfaFlowState state = new MfaFlowState();
        state.setUsername(USERNAME);
        Timestamp now = Timestamp.from(Instant.now());
        state.setCreatedDate(now);
        state.setUpdatedDate(now);
        state.setRecoveryEmailVerified(Boolean.FALSE);
        return state;
    }
}
