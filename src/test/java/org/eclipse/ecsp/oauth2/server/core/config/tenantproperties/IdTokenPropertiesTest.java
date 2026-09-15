/********************************************************************************
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
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdTokenPropertiesTest {

    @Test
    void getAdditionalClaimNamesParsesCommaSeparatedValues() {
        IdTokenProperties properties = new IdTokenProperties();
        properties.setAdditionalClaims(" email, profile, email, firstName ");

        assertEquals(List.of("email", "profile", "firstName"), properties.getAdditionalClaimNames());
    }

    @Test
    void mandatoryClaimsAreProtectedCaseInsensitively() {
        IdTokenProperties properties = new IdTokenProperties();

        List.of(
                JwtClaimNames.JTI,
                IdTokenClaimNames.ISS,
                IdTokenClaimNames.SUB,
                IdTokenClaimNames.AUD,
                IdTokenClaimNames.EXP,
                IdTokenClaimNames.IAT,
                IdTokenClaimNames.AUTH_TIME,
                IdTokenClaimNames.NONCE,
                IdTokenClaimNames.ACR,
                IdTokenClaimNames.AMR,
                IdTokenClaimNames.AZP,
                IdTokenClaimNames.AT_HASH,
                IdTokenClaimNames.C_HASH)
                .forEach(claimName -> assertTrue(properties.isMandatoryClaim(claimName)));

        assertTrue(properties.isMandatoryClaim("AUTH_TIME"));
        assertFalse(properties.isMandatoryClaim("email"));
    }

    @Test
    void additionalClaimsBindFromTenantProperties() {
        MapConfigurationPropertySource source = new MapConfigurationPropertySource(Map.of(
                "tenants.profile.ecsp.client.id-token-properties.additional-claims", "email,profile"));

        MultiTenantProperties properties = new Binder(source)
                .bind("tenants", Bindable.of(MultiTenantProperties.class))
                .orElseThrow(IllegalStateException::new);

        assertEquals(
                List.of("email", "profile"),
                properties.getTenantProperties("ecsp").getClient()
                        .getIdTokenProperties().getAdditionalClaimNames());
    }
}
