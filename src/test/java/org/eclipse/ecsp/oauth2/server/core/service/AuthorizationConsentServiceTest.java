package org.eclipse.ecsp.oauth2.server.core.service;

import org.eclipse.ecsp.oauth2.server.core.entities.AuthorizationConsent;
import org.eclipse.ecsp.oauth2.server.core.repositories.AuthorizationConsentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthorizationConsentServiceTest {

    @Mock
    AuthorizationConsentRepository authorizationConsentRepository;
    @Mock
    RegisteredClientRepository registeredClientRepository;

    AuthorizationConsentService authorizationConsentService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        authorizationConsentService = new AuthorizationConsentService(authorizationConsentRepository,
                registeredClientRepository);
    }

    @Test
    void findByIdReturnsNullWhenNotFound() {
        when(authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName("client-id", "principal-name"))
            .thenReturn(Optional.empty());

        OAuth2AuthorizationConsent result = authorizationConsentService.findById("client-id", "principal-name");
        assertNull(result);
    }

    @Test
    void findByIdThrowsExceptionWhenRegisteredClientNotFound() {
        AuthorizationConsent authorizationConsent = new AuthorizationConsent();
        authorizationConsent.setRegisteredClientId("client-id");
        authorizationConsent.setPrincipalName("principal-name");
        when(authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName("client-id",
                "principal-name"))
            .thenReturn(Optional.of(authorizationConsent));
        when(registeredClientRepository.findById("client-id")).thenReturn(null);

        assertThrows(DataRetrievalFailureException.class, () -> authorizationConsentService.findById(
                "client-id", "principal-name"));
    }

    @Test
    void findById_withRegisteredClientAndAuthorities_returnsConsent() {
        AuthorizationConsent entity = new AuthorizationConsent();
        entity.setRegisteredClientId("client-id");
        entity.setPrincipalName("principal-name");
        entity.setAuthorities("ROLE_USER,SCOPE_read");
        when(authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName("client-id",
                "principal-name"))
            .thenReturn(Optional.of(entity));

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClient.getId()).thenReturn("client-id");
        when(registeredClientRepository.findById("client-id")).thenReturn(registeredClient);

        OAuth2AuthorizationConsent result = authorizationConsentService.findById("client-id", "principal-name");

        assertNotNull(result);
    }

    @Test
    void findById_withRegisteredClientNullAuthorities_throwsIllegalArgument() {
        AuthorizationConsent entity = new AuthorizationConsent();
        entity.setRegisteredClientId("client-id");
        entity.setPrincipalName("principal-name");
        entity.setAuthorities(null);
        when(authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName("client-id",
                "principal-name"))
            .thenReturn(Optional.of(entity));

        RegisteredClient registeredClient = mock(RegisteredClient.class);
        when(registeredClient.getId()).thenReturn("client-id");
        when(registeredClientRepository.findById("client-id")).thenReturn(registeredClient);

        // null authorities causes OAuth2AuthorizationConsent builder to throw
        assertThrows(IllegalArgumentException.class,
                () -> authorizationConsentService.findById("client-id", "principal-name"));
    }

    @Test
    void save_persistsConsent() {
        OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent
                .withId("client-id", "principal-name")
                .authority(new SimpleGrantedAuthority("ROLE_USER"))
                .build();

        authorizationConsentService.save(consent);

        verify(authorizationConsentRepository).save(any(AuthorizationConsent.class));
    }

    @Test
    void remove_deletesConsent() {
        OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent
                .withId("client-id", "principal-name")
                .authority(new SimpleGrantedAuthority("ROLE_USER"))
                .build();

        authorizationConsentService.remove(consent);

        verify(authorizationConsentRepository)
                .deleteByRegisteredClientIdAndPrincipalName("client-id", "principal-name");
    }
}