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
 * Unit tests for PasswordAuthenticationContext.
 */
@SuppressWarnings("checkstyle:MagicNumber")
class PasswordAuthenticationContextTest {

    @Test
    void toMapShouldReturnAllFields() {
        // Given
        PasswordAuthenticationContext context = PasswordAuthenticationContext.builder()
            .failedAttempts(3)
            .authType("password")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("failed_attempts", 3);
        assertThat(map).containsEntry("auth_type", "password");
    }

    @Test
    void toMapWithZeroFailedAttemptsShouldWork() {
        // Given
        PasswordAuthenticationContext context = PasswordAuthenticationContext.builder()
            .failedAttempts(0)
            .authType("password")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("failed_attempts", 0);
        assertThat(map).containsEntry("auth_type", "password");
    }

    @Test
    void toMapWithHighFailedAttemptsShouldWork() {
        // Given
        PasswordAuthenticationContext context = PasswordAuthenticationContext.builder()
            .failedAttempts(5)
            .authType("password")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).hasSize(2);
        assertThat(map.get("failed_attempts")).isEqualTo(5);
    }

    @Test
    void builderShouldCreateValidInstance() {
        // When
        PasswordAuthenticationContext context = PasswordAuthenticationContext.builder()
            .failedAttempts(1)
            .authType("password")
            .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getFailedAttempts()).isEqualTo(1);
        assertThat(context.getAuthType()).isEqualTo("password");
    }

    @Test
    void toMapWithNullAuthTypeShouldWork() {
        // Given
        PasswordAuthenticationContext context = PasswordAuthenticationContext.builder()
            .failedAttempts(2)
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("failed_attempts", 2);
        assertThat(map).doesNotContainKey("auth_type");
    }

    @Test
    void toMapWithNullFailedAttemptsShouldWork() {
        // Given
        PasswordAuthenticationContext context = PasswordAuthenticationContext.builder()
            .authType("password")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("auth_type", "password");
        assertThat(map).doesNotContainKey("failed_attempts");
    }

    @Test
    void toMapForAccountLockedScenarioShouldWork() {
        // Given - representing account locked after max attempts
        PasswordAuthenticationContext context = PasswordAuthenticationContext.builder()
            .failedAttempts(5)
            .authType("password")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map.get("failed_attempts")).isEqualTo(5);
        assertThat(map).hasSize(2);
    }

    @Test
    void toMapForSuccessfulAuthAfterFailuresShouldWork() {
        // Given - tracking that there were previous failures
        PasswordAuthenticationContext context = PasswordAuthenticationContext.builder()
            .failedAttempts(2)
            .authType("password")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map.get("failed_attempts")).isEqualTo(2);
    }

    // Test getters work correctly

    @Test
    void gettershouldWork() {
        // When
        PasswordAuthenticationContext context = PasswordAuthenticationContext.builder()
            .failedAttempts(2)
            .authType("idp:google")
            .build();

        // Then
        assertThat(context.getFailedAttempts()).isEqualTo(2);
        assertThat(context.getAuthType()).isEqualTo("idp:google");
    }
}
