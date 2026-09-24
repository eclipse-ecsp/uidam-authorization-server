package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TenantPropertiesTest {

    private TenantProperties tenantProperties;

    @BeforeEach
    void setUp() {
        tenantProperties = new TenantProperties();
    }

    @Test
    void testParseMappings() {
        // Arrange
        ExternalIdpRegisteredClient client1 = new ExternalIdpRegisteredClient();
        client1.setClaimMappings("firstName#given_name,lastName#family_name,email#email");

        ExternalIdpRegisteredClient client2 = new ExternalIdpRegisteredClient();
        client2.setClaimMappings("username#sub");

        tenantProperties.setExternalIdpRegisteredClientList(Arrays.asList(client1, client2));

        // Act
        tenantProperties.parseMappings();

        // Assert
        HashMap<String, String> expectedMappingsClient1 = new HashMap<>();
        expectedMappingsClient1.put("firstName", "given_name");
        expectedMappingsClient1.put("lastName", "family_name");
        expectedMappingsClient1.put("email", "email");

        HashMap<String, String> expectedMappingsClient2 = new HashMap<>();
        expectedMappingsClient2.put("username", "sub");

        assertEquals(expectedMappingsClient1, client1.getMappings());
        assertEquals(expectedMappingsClient2, client2.getMappings());
    }

    @Test
    void externalIdpIdTokenInclusionDefaultsToFalseAndBindsWhenEnabled() {
        assertFalse(new ExternalIdpRegisteredClient().isIncludeIdpIdToken());

        MapConfigurationPropertySource source = new MapConfigurationPropertySource(Map.of(
                "tenants.profile.ecsp.external-idp-registered-client-list[0].enabled", "true",
                "tenants.profile.ecsp.external-idp-registered-client-list[0].registration-id", "google",
                "tenants.profile.ecsp.external-idp-registered-client-list[0]"
                        + ".include-idp-id-token", "true"));

        MultiTenantProperties properties = new Binder(source)
                .bind("tenants", Bindable.of(MultiTenantProperties.class))
                .orElseThrow(IllegalStateException::new);

        ExternalIdpRegisteredClient client = properties.getTenantProperties("ecsp")
                .getExternalIdpRegisteredClientList().get(0);
        assertTrue(client.isIncludeIdpIdToken());
    }
}
