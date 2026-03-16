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

package org.eclipse.ecsp.oauth2.server.core.request.dto;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test class for AdminGetActiveSessionsRequestDto.
 */
class AdminGetActiveSessionsRequestDtoTest {
    
    private static Validator validator;
    
    @BeforeAll
    static void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }
    
    @Test
    void testBuilder() {
        // Arrange & Act
        AdminGetActiveSessionsRequestDto dto = AdminGetActiveSessionsRequestDto.builder()
                .username("test.user@example.com")
                .build();
        
        // Assert
        assertNotNull(dto);
        assertEquals("test.user@example.com", dto.getUsername());
    }
    
    @Test
    void testNoArgsConstructor() {
        // Arrange & Act
        AdminGetActiveSessionsRequestDto dto = new AdminGetActiveSessionsRequestDto();
        
        // Assert
        assertNotNull(dto);
        assertNull(dto.getUsername());
    }
    
    @Test
    void testAllArgsConstructor() {
        // Arrange
        String username = "admin@example.com";
        
        // Act
        AdminGetActiveSessionsRequestDto dto = new AdminGetActiveSessionsRequestDto(username);
        
        // Assert
        assertNotNull(dto);
        assertEquals(username, dto.getUsername());
    }
    
    @Test
    void testGettersAndSetters() {
        // Arrange
        AdminGetActiveSessionsRequestDto dto = new AdminGetActiveSessionsRequestDto();
        String username = "setter.user@example.com";
        
        // Act
        dto.setUsername(username);
        
        // Assert
        assertEquals(username, dto.getUsername());
    }
    
    @Test
    void testValidDto() {
        // Arrange
        AdminGetActiveSessionsRequestDto dto = AdminGetActiveSessionsRequestDto.builder()
                .username("valid.user@example.com")
                .build();
        
        // Act
        Set<ConstraintViolation<AdminGetActiveSessionsRequestDto>> violations = validator.validate(dto);
        
        // Assert
        assertTrue(violations.isEmpty(), "Valid DTO should have no violations");
    }
    
    @Test
    void testNullUsername() {
        // Arrange
        AdminGetActiveSessionsRequestDto dto = AdminGetActiveSessionsRequestDto.builder()
                .username(null)
                .build();
        
        // Act
        Set<ConstraintViolation<AdminGetActiveSessionsRequestDto>> violations = validator.validate(dto);
        
        // Assert
        assertFalse(violations.isEmpty(), "Null username should cause validation error");
        assertEquals(1, violations.size());
        assertTrue(violations.stream()
                .anyMatch(v -> v.getMessage().contains("username is required")));
    }
    
    @Test
    void testBlankUsername() {
        // Arrange
        AdminGetActiveSessionsRequestDto dto = AdminGetActiveSessionsRequestDto.builder()
                .username("   ")
                .build();
        
        // Act
        Set<ConstraintViolation<AdminGetActiveSessionsRequestDto>> violations = validator.validate(dto);
        
        // Assert
        assertFalse(violations.isEmpty(), "Blank username should cause validation error");
    }
    
    @Test
    void testEmptyUsername() {
        // Arrange
        AdminGetActiveSessionsRequestDto dto = AdminGetActiveSessionsRequestDto.builder()
                .username("")
                .build();
        
        // Act
        Set<ConstraintViolation<AdminGetActiveSessionsRequestDto>> violations = validator.validate(dto);
        
        // Assert
        assertFalse(violations.isEmpty(), "Empty username should cause validation error");
    }
    
    @Test
    void testEqualsAndHashCode() {
        // Arrange
        AdminGetActiveSessionsRequestDto dto1 = AdminGetActiveSessionsRequestDto.builder()
                .username("user@example.com")
                .build();
        
        AdminGetActiveSessionsRequestDto dto2 = AdminGetActiveSessionsRequestDto.builder()
                .username("user@example.com")
                .build();
        
        AdminGetActiveSessionsRequestDto dto3 = AdminGetActiveSessionsRequestDto.builder()
                .username("different@example.com")
                .build();
        
        // Assert
        assertEquals(dto1, dto2, "DTOs with same data should be equal");
        assertEquals(dto1.hashCode(), dto2.hashCode(), "DTOs with same data should have same hash code");
        assertNotEquals(dto1, dto3, "DTOs with different data should not be equal");
    }
    
    @Test
    void testToString() {
        // Arrange
        AdminGetActiveSessionsRequestDto dto = AdminGetActiveSessionsRequestDto.builder()
                .username("user@example.com")
                .build();
        
        // Act
        String toString = dto.toString();
        
        // Assert
        assertNotNull(toString);
        assertTrue(toString.contains("user@example.com"));
    }
}
