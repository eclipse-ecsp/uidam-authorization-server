package org.eclipse.ecsp.oauth2.server.core.mfa;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for MFA behaviour.
 *
 * <p>Example {@code application.properties}:
 * <pre>
 * mfa.enabled=true
 * </pre>
 */
@Component
@ConfigurationProperties(prefix = "mfa")
public class MfaProperties {

    /** Master switch: whether MFA is enforced at all. */
    private boolean enabled = true;

    /** Application name shown in authenticator apps and MFA UI pages. Default: UIDAM. */
    private String appName = "UIDAM";

    /** Recovery sub-properties. */
    private Recovery recovery = new Recovery();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public Recovery getRecovery() {
        return recovery;
    }

    public void setRecovery(Recovery recovery) {
        this.recovery = recovery;
    }

    /**
     * Nested properties for email-based MFA recovery.
     */
    public static class Recovery {

        /** Cooldown in seconds before the user can request another recovery email. Default: 60. */
        private int resendCooldownSeconds = 60;

        public int getResendCooldownSeconds() {
            return resendCooldownSeconds;
        }

        public void setResendCooldownSeconds(int resendCooldownSeconds) {
            this.resendCooldownSeconds = resendCooldownSeconds;
        }
    }
}