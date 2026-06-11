package org.eclipse.ecsp.oauth2.server.core.mfa;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

/**
 * Intermediate Spring Security token representing a user who has passed
 * password authentication but has NOT yet completed the MFA challenge.
 *
 * <p>{@code isAuthenticated()} always returns {@code false}.
 */
public class MfaPendingAuthenticationToken extends AbstractAuthenticationToken {

    private final String username;
    private final Collection<GrantedAuthority> pendingAuthorities;

    /**
     * Constructs a pending MFA token for the given user.
     *
     * @param username the authenticated username (password check passed).
     * @param pending  the authorities that will be granted after MFA is verified.
     */
    @SuppressWarnings("unchecked")
    public MfaPendingAuthenticationToken(String username,
                                         Collection<? extends GrantedAuthority> pending) {
        super(Collections.emptyList());
        this.username = username;
        this.pendingAuthorities = Collections.unmodifiableCollection(
                (Collection<GrantedAuthority>) pending);
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return username;
    }

    /**
     * Return the authorities that will be granted once MFA is verified.
     *
     * @return unmodifiable collection of pending authorities.
     */
    public Collection<GrantedAuthority> getPendingAuthorities() {
        return pendingAuthorities;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof MfaPendingAuthenticationToken that)) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        return Objects.equals(username, that.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), username);
    }
}
