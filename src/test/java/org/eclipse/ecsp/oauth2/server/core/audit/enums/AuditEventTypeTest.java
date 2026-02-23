/*
 * Copyright (c) 2024 - 2025 Harman International
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.oauth2.server.core.audit.enums;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for AuditEventType enum.
 */
class AuditEventTypeTest {

    @Test
    void getType_ShouldReturnEventTypeString() {
        // When/Then
        assertThat(AuditEventType.AUTH_SUCCESS_PASSWORD.getType())
            .isEqualTo("AUTH_SUCCESS_PASSWORD");
        assertThat(AuditEventType.LOGOUT.getType())
            .isEqualTo("LOGOUT");
        assertThat(AuditEventType.AUTHZ_FAILURE_REVOKED_TOKEN.getType())
            .isEqualTo("AUTHZ_FAILURE_REVOKED_TOKEN");
    }

    @Test
    void getDescription_ShouldReturnHumanReadableText() {
        // When/Then
        assertThat(AuditEventType.AUTH_SUCCESS_PASSWORD.getDescription())
            .isEqualTo("User authenticated successfully via password");
        assertThat(AuditEventType.AUTH_FAILURE_WRONG_PASSWORD.getDescription())
            .isEqualTo("User authentication failed - wrong password");
    }

    @Test
    void isAuthentication_ShouldReturnTrueForAuthEvents() {
        // When/Then
        assertThat(AuditEventType.AUTH_SUCCESS_PASSWORD.isAuthentication()).isTrue();
        assertThat(AuditEventType.AUTH_SUCCESS_IDP.isAuthentication()).isTrue();
        assertThat(AuditEventType.AUTH_FAILURE_WRONG_PASSWORD.isAuthentication()).isTrue();
        assertThat(AuditEventType.AUTH_FAILURE_USER_NOT_FOUND.isAuthentication()).isTrue();
        assertThat(AuditEventType.AUTH_FAILURE_USER_BLOCKED.isAuthentication()).isTrue();
        assertThat(AuditEventType.AUTH_FAILURE_ACCOUNT_NOT_FOUND.isAuthentication()).isTrue();
        assertThat(AuditEventType.AUTH_FAILURE_ACCOUNT_LOCKED.isAuthentication()).isTrue();
        assertThat(AuditEventType.AUTH_FAILURE_CAPTCHA.isAuthentication()).isTrue();
        assertThat(AuditEventType.LOGOUT.isAuthentication()).isTrue();
        assertThat(AuditEventType.TOKEN_REFRESHED.isAuthentication()).isTrue();
        assertThat(AuditEventType.ACCESS_TOKEN_GENERATED.isAuthentication()).isTrue();
    }

    @Test
    void isAuthentication_ShouldReturnFalseForNonAuthEvents() {
        // When/Then
        assertThat(AuditEventType.AUTHZ_FAILURE_REVOKED_TOKEN.isAuthentication()).isFalse();
    }

    @Test
    void isAuthorization_ShouldReturnTrueForAuthzEvents() {
        // When/Then
        assertThat(AuditEventType.AUTHZ_FAILURE_REVOKED_TOKEN.isAuthorization()).isTrue();
    }

    @Test
    void isAuthorization_ShouldReturnFalseForNonAuthzEvents() {
        // When/Then
        assertThat(AuditEventType.AUTH_SUCCESS_PASSWORD.isAuthorization()).isFalse();
        assertThat(AuditEventType.LOGOUT.isAuthorization()).isFalse();
        assertThat(AuditEventType.TOKEN_REFRESHED.isAuthorization()).isFalse();
    }

    @Test
    void fromType_WithValidType_ShouldReturnMatchingEnum() {
        // When/Then
        assertThat(AuditEventType.fromType("AUTH_SUCCESS_PASSWORD"))
            .isEqualTo(AuditEventType.AUTH_SUCCESS_PASSWORD);
        assertThat(AuditEventType.fromType("LOGOUT"))
            .isEqualTo(AuditEventType.LOGOUT);
        assertThat(AuditEventType.fromType("AUTHZ_FAILURE_REVOKED_TOKEN"))
            .isEqualTo(AuditEventType.AUTHZ_FAILURE_REVOKED_TOKEN);
    }

    @Test
    void fromType_WithNullType_ShouldReturnNull() {
        // When/Then
        assertThat(AuditEventType.fromType(null)).isNull();
    }

    @Test
    void fromType_WithInvalidType_ShouldReturnNull() {
        // When/Then
        assertThat(AuditEventType.fromType("INVALID_TYPE")).isNull();
        assertThat(AuditEventType.fromType("")).isNull();
    }

    @Test
    void toString_ShouldReturnEventType() {
        // When/Then
        assertThat(AuditEventType.AUTH_SUCCESS_PASSWORD.toString())
            .isEqualTo("AUTH_SUCCESS_PASSWORD");
        assertThat(AuditEventType.LOGOUT.toString())
            .isEqualTo("LOGOUT");
    }

    @Test
    void values_ShouldReturnAllEnumConstants() {
        // When
        AuditEventType[] values = AuditEventType.values();
        
        // Then
        assertThat(values).isNotEmpty();
        assertThat(values).contains(
            AuditEventType.AUTH_SUCCESS_PASSWORD,
            AuditEventType.AUTH_SUCCESS_IDP,
            AuditEventType.AUTH_FAILURE_WRONG_PASSWORD,
            AuditEventType.AUTH_FAILURE_USER_NOT_FOUND,
            AuditEventType.AUTH_FAILURE_USER_BLOCKED,
            AuditEventType.AUTH_FAILURE_ACCOUNT_NOT_FOUND,
            AuditEventType.AUTH_FAILURE_ACCOUNT_LOCKED,
            AuditEventType.AUTH_FAILURE_CAPTCHA,
            AuditEventType.LOGOUT,
            AuditEventType.TOKEN_REFRESHED,
            AuditEventType.ACCESS_TOKEN_GENERATED,
            AuditEventType.AUTHZ_FAILURE_REVOKED_TOKEN
        );
    }

    @Test
    void valueOf_WithValidName_ShouldReturnEnum() {
        // When/Then
        assertThat(AuditEventType.valueOf("AUTH_SUCCESS_PASSWORD"))
            .isEqualTo(AuditEventType.AUTH_SUCCESS_PASSWORD);
        assertThat(AuditEventType.valueOf("LOGOUT"))
            .isEqualTo(AuditEventType.LOGOUT);
    }
}
