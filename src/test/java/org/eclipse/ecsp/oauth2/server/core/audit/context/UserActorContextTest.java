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
        assertThat(map).containsEntry("actorId", "user123");
        assertThat(map).containsEntry("username", "john.doe");
        assertThat(map).containsEntry("accountName", "John Doe");
        assertThat(map).containsEntry("accountId", "acc456");
        assertThat(map).containsEntry("accountId", "acc456");
        assertThat(map).containsEntry("accountName", "John Doe");
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
}
