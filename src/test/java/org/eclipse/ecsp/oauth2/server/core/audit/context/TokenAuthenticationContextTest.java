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
}
