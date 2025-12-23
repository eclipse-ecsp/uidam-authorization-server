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
 * Unit tests for UserActorContext.
 */
@SuppressWarnings("checkstyle:MagicNumber")
class UserActorContextTest {

    @Test
    void toMapShouldReturnAllFields() {
        // Given
        UserActorContext context = UserActorContext.builder()
            .userId("user123")
            .username("john.doe")
            .accountId("acc456")
            .accountName("John Doe")
            .failedAttempts(3)
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("actorId", "user123");
        assertThat(map).containsEntry("actorType", "USER");
        assertThat(map).containsEntry("username", "john.doe");
        assertThat(map).containsEntry("accountName", "John Doe");
        assertThat(map).containsEntry("accountId", "acc456");
        assertThat(map).containsEntry("failedAttempts", 3);
        assertThat(map).hasSize(6);
    }

    @Test
    void toMapWithNullValuesShouldNotIncludeNullFields() {
        // Given
        UserActorContext context = UserActorContext.builder()
            .userId("user123")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("actorId", "user123");
        assertThat(map).containsEntry("actorType", "USER");
        assertThat(map).doesNotContainKey("username");
        assertThat(map).doesNotContainKey("accountName");
        assertThat(map).doesNotContainKey("accountId");
        assertThat(map).doesNotContainKey("failedAttempts");
        assertThat(map).hasSize(2);
    }

    @Test
    void toMapWithMinimalDataShouldWork() {
        // Given
        UserActorContext context = UserActorContext.builder()
            .userId("user999")
            .username("test.user")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).hasSize(3); // actorId, actorType, username
        assertThat(map.get("actorId")).isEqualTo("user999");
        assertThat(map.get("username")).isEqualTo("test.user");
    }

    @Test
    void builderShouldCreateValidInstance() {
        // When
        UserActorContext context = UserActorContext.builder()
            .userId("user111")
            .username("alice")
            .accountId("tenant222")
            .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getUserId()).isEqualTo("user111");
        assertThat(context.getUsername()).isEqualTo("alice");
        assertThat(context.getAccountId()).isEqualTo("tenant222");
    }

    @Test
    void toMapShouldUseUserIdAsActorId() {
        // Given
        UserActorContext context = UserActorContext.builder()
            .userId("specific-user-id-123")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map.get("actorId")).isEqualTo("specific-user-id-123");
    }

    @Test
    void toMapShouldAlwaysSetActorTypeToUser() {
        // Given
        UserActorContext context = UserActorContext.builder()
            .userId("user456")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map.get("actorType")).isEqualTo("USER");
    }

    @Test
    void toMapWithFailedAttemptsShouldIncludeCount() {
        // Given
        UserActorContext context = UserActorContext.builder()
            .userId("user789")
            .failedAttempts(5)
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("failedAttempts", 5);
    }

    @Test
    void toMapWithZeroFailedAttemptsShouldIncludeZero() {
        // Given
        UserActorContext context = UserActorContext.builder()
            .userId("user000")
            .failedAttempts(0)
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("failedAttempts", 0);
    }

    @Test
    void toMapWithAccountFieldsShouldWork() {
        // Given
        UserActorContext context = UserActorContext.builder()
            .userId("user555")
            .accountId("acc999")
            .accountName("Test Account")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).containsEntry("accountId", "acc999");
        assertThat(map).containsEntry("accountName", "Test Account");
        assertThat(map).hasSize(4); // actorId, actorType, accountId, accountName
    }

    // Tests for Lombok-generated methods

    @Test
    void equalsShouldReturnTrueForSameValues() {
        // Given
        UserActorContext context1 = UserActorContext.builder()
            .userId("user123")
            .username("john.doe")
            .accountId("acc456")
            .accountName("John Doe")
            .failedAttempts(3)
            .build();

        UserActorContext context2 = UserActorContext.builder()
            .userId("user123")
            .username("john.doe")
            .accountId("acc456")
            .accountName("John Doe")
            .failedAttempts(3)
            .build();

        // Then
        assertThat(context1).isEqualTo(context2);
        assertThat(context1.hashCode()).isEqualTo(context2.hashCode());
    }

    @Test
    void equalsShouldReturnFalseForDifferentValues() {
        // Given
        UserActorContext context1 = UserActorContext.builder()
            .userId("user123")
            .username("john.doe")
            .build();

        UserActorContext context2 = UserActorContext.builder()
            .userId("user456")
            .username("jane.smith")
            .build();

        // Then
        assertThat(context1).isNotEqualTo(context2);
    }

    @Test
    void equalsShouldHandleNullFields() {
        // Given
        UserActorContext context1 = UserActorContext.builder()
            .userId("user123")
            .build();

        UserActorContext context2 = UserActorContext.builder()
            .userId("user123")
            .build();

        // Then
        assertThat(context1).isEqualTo(context2);
    }

    @Test
    void toStringShouldIncludeAllFields() {
        // Given
        UserActorContext context = UserActorContext.builder()
            .userId("user123")
            .username("john.doe")
            .accountId("acc456")
            .accountName("John Doe")
            .failedAttempts(3)
            .build();

        // When
        String str = context.toString();

        // Then
        assertThat(str).contains("user123");
        assertThat(str).contains("john.doe");
        assertThat(str).contains("acc456");
        assertThat(str).contains("John Doe");
        assertThat(str).contains("3");
    }

    @Test
    void gettersAndSettersShouldWork() {
        // When
        UserActorContext context = UserActorContext.builder()
            .userId("user999")
            .username("test.user")
            .accountId("acc111")
            .accountName("Test Account")
            .failedAttempts(7)
            .build();

        // Then
        assertThat(context.getUserId()).isEqualTo("user999");
        assertThat(context.getUsername()).isEqualTo("test.user");
        assertThat(context.getAccountId()).isEqualTo("acc111");
        assertThat(context.getAccountName()).isEqualTo("Test Account");
        assertThat(context.getFailedAttempts()).isEqualTo(7);
    }

    @Test
    void builderShouldSupportPartialFieldsChaining() {
        // When
        UserActorContext context = UserActorContext.builder()
            .userId("user111")
            .build();

        // Then
        assertThat(context.getUserId()).isEqualTo("user111");
        assertThat(context.getUsername()).isNull();
        assertThat(context.getAccountId()).isNull();
        assertThat(context.getAccountName()).isNull();
        assertThat(context.getFailedAttempts()).isNull();
    }

    @Test
    void builderShouldHandleNullValues() {
        // When
        UserActorContext context = UserActorContext.builder()
            .userId("user222")
            .username(null)
            .accountId(null)
            .accountName(null)
            .failedAttempts(null)
            .build();

        // Then
        assertThat(context.getUserId()).isEqualTo("user222");
        assertThat(context.getUsername()).isNull();
        assertThat(context.getAccountId()).isNull();
        assertThat(context.getAccountName()).isNull();
        assertThat(context.getFailedAttempts()).isNull();
    }

    @Test
    void toMapWithOnlyFailedAttemptsShouldWork() {
        // Given
        UserActorContext context = UserActorContext.builder()
            .userId("user333")
            .failedAttempts(10)
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).hasSize(3); // actorId, actorType, failedAttempts
        assertThat(map).containsEntry("failedAttempts", 10);
    }

    @Test
    void equalsShouldHandleDifferentFailedAttempts() {
        // Given
        UserActorContext context1 = UserActorContext.builder()
            .userId("user123")
            .failedAttempts(3)
            .build();

        UserActorContext context2 = UserActorContext.builder()
            .userId("user123")
            .failedAttempts(5)
            .build();

        // Then
        assertThat(context1).isNotEqualTo(context2);
    }

    @Test
    void toMapShouldNotIncludeFailedAttemptsWhenNull() {
        // Given
        UserActorContext context = UserActorContext.builder()
            .userId("user444")
            .username("test")
            .accountId("acc555")
            .build();

        // When
        Map<String, Object> map = context.toMap();

        // Then
        assertThat(map).doesNotContainKey("failedAttempts");
    }
}
