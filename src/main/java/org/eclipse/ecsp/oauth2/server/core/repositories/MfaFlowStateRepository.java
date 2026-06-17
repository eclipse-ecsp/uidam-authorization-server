package org.eclipse.ecsp.oauth2.server.core.repositories;

import org.eclipse.ecsp.oauth2.server.core.entities.MfaFlowState;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repository for per-user MFA recovery-flow state.
 *
 * <p>Provides CRUD access to {@link MfaFlowState} records keyed by username.
 * Used by the MFA flow to persist recovery rate-limit and email-verification
 * state across pods without relying on {@code HttpSession}.
 */
public interface MfaFlowStateRepository extends JpaRepository<MfaFlowState, String> {
    // findById(username) and save() from JpaRepository are sufficient.
}
