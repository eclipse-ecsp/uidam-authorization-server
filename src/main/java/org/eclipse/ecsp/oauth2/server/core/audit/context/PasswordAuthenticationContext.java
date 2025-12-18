package org.eclipse.ecsp.oauth2.server.core.audit.context;

import lombok.Builder;
import lombok.Getter;
import org.eclipse.ecsp.audit.context.AuthenticationContext;

import java.util.HashMap;
import java.util.Map;

/**
 * Authentication context for password-based authentication events.
 * Captures structured metadata about password authentication attempts including the number 
 * of failed attempts. Can be used for both successful and failed authentication events.
 *
 * <p>This context is used for events like:
 * <ul>
 * <li>AUTH_SUCCESS_PASSWORD: Shows failed attempts before success (e.g., succeeded after 2 failed attempts)</li>
 * <li>AUTH_FAILURE_WRONG_PASSWORD: Shows current failed attempt count</li>
 * <li>AUTH_FAILURE_ACCOUNT_LOCKED: Shows total failed attempts that triggered the lock</li>
 * </ul>
 *
 * <p>This provides structured data rather than embedding attempt counts in message strings.
 */
@Getter
@Builder
public class PasswordAuthenticationContext implements AuthenticationContext {
    
    /**
     * The number of consecutive failed login attempts for this user.
     * This count is incremented with each failed authentication and is used to
     * determine when to lock the account or show captcha.
     */
    private final Integer failedAttempts;
    
    /**
     * The authentication method that failed (e.g., "password", "idp:google").
     * Optional field to provide additional context about the authentication type.
     */
    private final String authType;
    
    /**
     * Converts this context to a Map for JSON serialization in audit logs.
     *
     * @return Map containing failed_attempts and optionally auth_type
     */
    @Override
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        if (failedAttempts != null) {
            map.put("failed_attempts", failedAttempts);
        }
        if (authType != null && !authType.isEmpty()) {
            map.put("auth_type", authType);
        }
        return map;
    }
}
