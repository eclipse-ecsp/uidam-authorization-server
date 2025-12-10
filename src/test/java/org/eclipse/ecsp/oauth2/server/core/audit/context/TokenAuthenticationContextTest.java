/********************************************************************************
 * Copyright (c) 2024-25 Harman International 
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

package org.eclipse.ecsp.oauth2.server.core.audit.context;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for TokenAuthenticationContext.
 */
@SuppressWarnings("checkstyle:MagicNumber")
class TokenAuthenticationContextTest {

    @Test
    void toMapShouldReturnAllFields() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .authType("password")
            .clientId("client123")
            .scopes("read write")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("grant_type", "authorization_code");
        assertThat(map).containsEntry("auth_type", "password");
        assertThat(map).containsEntry("client_id", "client123");
        assertThat(map).containsEntry("scopes", "read write");
        assertThat(map).hasSize(4);
    }

    @Test
    void toMapWithNullValuesShouldNotIncludeNullFields() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("refresh_token")
            .authType("password")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("grant_type", "refresh_token");
        assertThat(map).containsEntry("auth_type", "password");
        assertThat(map).doesNotContainKey("client_id");
        assertThat(map).doesNotContainKey("scopes");
        assertThat(map).hasSize(2);
    }

    @Test
    void toMapWithClientCredentialsShouldWork() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("client_credentials")
            .authType("client_credentials")
            .clientId("service-client-456")
            .scopes("service.read service.write")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).hasSize(4);
        assertThat(map.get("grant_type")).isEqualTo("client_credentials");
        assertThat(map.get("auth_type")).isEqualTo("client_credentials");
        assertThat(map.get("client_id")).isEqualTo("service-client-456");
        assertThat(map.get("scopes")).isEqualTo("service.read service.write");
    }

    @Test
    void builderShouldCreateValidInstance() {
        // When
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("password")
            .authType("password")
            .clientId("web-client")
            .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getGrantType()).isEqualTo("password");
        assertThat(context.getAuthType()).isEqualTo("password");
        assertThat(context.getClientId()).isEqualTo("web-client");
        assertThat(context.getScopes()).isNull();
    }

    @Test
    void toMapWithRefreshTokenGrantShouldWork() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("refresh_token")
            .authType("password")
            .clientId("mobile-app")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map.get("grant_type")).isEqualTo("refresh_token");
        assertThat(map.get("client_id")).isEqualTo("mobile-app");
        assertThat(map).hasSize(3);
    }

    @Test
    void toMapWithIdpAuthTypeShouldWork() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .authType("idp:google")
            .clientId("web-client")
            .scopes("openid profile email")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map.get("auth_type")).isEqualTo("idp:google");
        assertThat(map.get("scopes")).isEqualTo("openid profile email");
        assertThat(map).hasSize(4);
    }

    @Test
    void toMapWithMinimalFieldsShouldWork() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).hasSize(1);
        assertThat(map).containsEntry("grant_type", "authorization_code");
    }

    @Test
    void toMapWithOnlyGrantTypeAndClientIdShouldWork() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("client_credentials")
            .clientId("service-app")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).hasSize(2);
        assertThat(map).containsEntry("grant_type", "client_credentials");
        assertThat(map).containsEntry("client_id", "service-app");
    }

    @Test
    void toMapWithOnlyAuthTypeAndScopesShouldWork() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .authType("password")
            .scopes("openid email")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).hasSize(2);
        assertThat(map).containsEntry("auth_type", "password");
        assertThat(map).containsEntry("scopes", "openid email");
    }

    @Test
    void toMapWithAllNullValuesShouldReturnEmptyMap() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).isEmpty();
    }

    // Tests for Lombok-generated methods

    @Test
    void equalsShouldReturnTrueForSameValues() {
        // Given
        TokenAuthenticationContext context1 = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .authType("password")
            .clientId("client123")
            .scopes("read write")
            .build();

        TokenAuthenticationContext context2 = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .authType("password")
            .clientId("client123")
            .scopes("read write")
            .build();

        // Then
        assertThat(context1).isEqualTo(context2);
        assertThat(context1.hashCode()).isEqualTo(context2.hashCode());
    }

    @Test
    void equalsShouldReturnFalseForDifferentValues() {
        // Given
        TokenAuthenticationContext context1 = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .clientId("client123")
            .build();

        TokenAuthenticationContext context2 = TokenAuthenticationContext.builder()
            .grantType("refresh_token")
            .clientId("client456")
            .build();

        // Then
        assertThat(context1).isNotEqualTo(context2);
    }

    @Test
    void equalsShouldHandleNullFields() {
        // Given
        TokenAuthenticationContext context1 = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .build();

        TokenAuthenticationContext context2 = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .build();

        // Then
        assertThat(context1).isEqualTo(context2);
    }

    @Test
    void equalsShouldHandleDifferentGrantTypes() {
        // Given
        TokenAuthenticationContext context1 = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .authType("password")
            .build();

        TokenAuthenticationContext context2 = TokenAuthenticationContext.builder()
            .grantType("client_credentials")
            .authType("password")
            .build();

        // Then
        assertThat(context1).isNotEqualTo(context2);
    }

    @Test
    void equalsShouldHandleDifferentAuthTypes() {
        // Given
        TokenAuthenticationContext context1 = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .authType("password")
            .build();

        TokenAuthenticationContext context2 = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .authType("idp:google")
            .build();

        // Then
        assertThat(context1).isNotEqualTo(context2);
    }

    @Test
    void equalsShouldHandleDifferentClientIds() {
        // Given
        TokenAuthenticationContext context1 = TokenAuthenticationContext.builder()
            .clientId("client123")
            .build();

        TokenAuthenticationContext context2 = TokenAuthenticationContext.builder()
            .clientId("client456")
            .build();

        // Then
        assertThat(context1).isNotEqualTo(context2);
    }

    @Test
    void equalsShouldHandleDifferentScopes() {
        // Given
        TokenAuthenticationContext context1 = TokenAuthenticationContext.builder()
            .scopes("read write")
            .build();

        TokenAuthenticationContext context2 = TokenAuthenticationContext.builder()
            .scopes("read")
            .build();

        // Then
        assertThat(context1).isNotEqualTo(context2);
    }

    @Test
    void toStringShouldIncludeAllFields() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .authType("password")
            .clientId("client123")
            .scopes("read write")
            .build();

        // When
        String str = context.toString();

        // Then
        assertThat(str).contains("authorization_code");
        assertThat(str).contains("password");
        assertThat(str).contains("client123");
        assertThat(str).contains("read write");
    }

    @Test
    void toStringShouldHandleNullValues() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .build();

        // When
        String str = context.toString();

        // Then
        assertThat(str).contains("authorization_code");
        assertThat(str).contains("null");
    }

    @Test
    void gettersAndSettersShouldWork() {
        // When
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("password")
            .authType("password")
            .clientId("test-client")
            .scopes("openid profile")
            .build();

        // Then
        assertThat(context.getGrantType()).isEqualTo("password");
        assertThat(context.getAuthType()).isEqualTo("password");
        assertThat(context.getClientId()).isEqualTo("test-client");
        assertThat(context.getScopes()).isEqualTo("openid profile");
    }

    @Test
    void builderShouldSupportPartialFieldsChaining() {
        // When
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("refresh_token")
            .build();

        // Then
        assertThat(context.getGrantType()).isEqualTo("refresh_token");
        assertThat(context.getAuthType()).isNull();
        assertThat(context.getClientId()).isNull();
        assertThat(context.getScopes()).isNull();
    }

    @Test
    void builderShouldHandleExplicitNullValues() {
        // When
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("authorization_code")
            .authType(null)
            .clientId(null)
            .scopes(null)
            .build();

        // Then
        assertThat(context.getGrantType()).isEqualTo("authorization_code");
        assertThat(context.getAuthType()).isNull();
        assertThat(context.getClientId()).isNull();
        assertThat(context.getScopes()).isNull();
    }

    @Test
    void toMapWithPasswordGrantTypeShouldWork() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("password")
            .authType("password")
            .clientId("web-client")
            .scopes("openid email profile")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).hasSize(4);
        assertThat(map).containsEntry("grant_type", "password");
        assertThat(map).containsEntry("auth_type", "password");
        assertThat(map).containsEntry("client_id", "web-client");
        assertThat(map).containsEntry("scopes", "openid email profile");
    }

    @Test
    void toMapWithEmptyStringShouldIncludeField() {
        // Given
        TokenAuthenticationContext context = TokenAuthenticationContext.builder()
            .grantType("")
            .authType("")
            .clientId("")
            .scopes("")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).hasSize(4);
        assertThat(map).containsEntry("grant_type", "");
        assertThat(map).containsEntry("auth_type", "");
        assertThat(map).containsEntry("client_id", "");
        assertThat(map).containsEntry("scopes", "");
    }
}
