package org.eclipse.ecsp.oauth2.server.core.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.sql.Timestamp;

/**
 * Per-user MFA recovery-flow state stored in the shared database.
 *
 * <p>Replaces the {@code HttpSession} attributes that previously tracked:
 * <ul>
 *   <li>{@code MFA_RECOVERY_SENT_AT}       – epoch-ms timestamp of the last recovery-email send
 *       (used for rate-limiting repeated email requests).</li>
 *   <li>{@code MFA_RECOVERY_EMAIL_VERIFIED} – flag that gates the optional backup-code step
 *       in the account-recovery flow.</li>
 * </ul>
 *
 * <p>Keyed by username, so the record survives across pods and server restarts.
 */
@Getter
@Setter
@Entity
@ToString
@Table(name = "`mfa_flow_state`")
public class MfaFlowState {

    @Id
    @Column(name = "USERNAME", nullable = false)
    private String username;

    /**
     * Timestamp of the last recovery-key email send.  {@code null} means no email has been sent
     * yet in the current recovery attempt.
     */
    @Column(name = "RECOVERY_SENT_AT")
    private Timestamp recoverySentAt;

    /**
     * {@code true} after the user has successfully verified the email recovery key.
     * Guards the optional backup-code entry step that follows.
     */
    @Column(name = "RECOVERY_EMAIL_VERIFIED", nullable = false)
    private Boolean recoveryEmailVerified = Boolean.FALSE;

    @Column(name = "CREATED_DATE", nullable = false)
    private Timestamp createdDate;

    @Column(name = "UPDATED_DATE", nullable = false)
    private Timestamp updatedDate;
}
