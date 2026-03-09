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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test class for InvalidateSessionsRequestDto.
 */
class InvalidateSessionsRequestDtoTest {
    
    private static Validator validator;
    
    @BeforeAll
    static void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }
    
    @Test
    void testBuilder() {
        // Arrange & Act
        final int expectedSize = 3;
        InvalidateSessionsRequestDto dto = InvalidateSessionsRequestDto.builder()
                .tokenIds(Arrays.asList("token1", "token2", "token3"))
                .build();
        
        // Assert
        assertNotNull(dto);
        assertEquals(expectedSize, dto.getTokenIds().size());
        assertTrue(dto.getTokenIds().contains("token1"));
        assertTrue(dto.getTokenIds().contains("token2"));
        assertTrue(dto.getTokenIds().contains("token3"));
    }
    
    @Test
    void testNoArgsConstructor() {
        // Arrange & Act
        InvalidateSessionsRequestDto dto = new InvalidateSessionsRequestDto();
        
        // Assert
        assertNotNull(dto);
        assertNull(dto.getTokenIds());
    }
    
    @Test
    void testAllArgsConstructor() {
        // Arrange
        final int expectedSize = 2;
        List<String> tokenIds = Arrays.asList("token-a", "token-b");
        
        // Act
        InvalidateSessionsRequestDto dto = new InvalidateSessionsRequestDto(tokenIds);
        
        // Assert
        assertNotNull(dto);
        assertEquals(expectedSize, dto.getTokenIds().size());
        assertEquals(tokenIds, dto.getTokenIds());
    }
    
    @Test
    void testGettersAndSetters() {
        // Arrange
        InvalidateSessionsRequestDto dto = new InvalidateSessionsRequestDto();
        List<String> tokenIds = Collections.singletonList("single-token");
        
        // Act
        dto.setTokenIds(tokenIds);
        
        // Assert
        assertEquals(tokenIds, dto.getTokenIds());
    }
    
    @Test
    void testValidDto() {
        // Arrange
        InvalidateSessionsRequestDto dto = InvalidateSessionsRequestDto.builder()
                .tokenIds(Arrays.asList("token1", "token2"))
                .build();
        
        // Act
        Set<ConstraintViolation<InvalidateSessionsRequestDto>> violations = validator.validate(dto);
        
        // Assert
        assertTrue(violations.isEmpty(), "Valid DTO should have no violations");
    }
    
    @Test
    void testNullTokenIds() {
        // Arrange
        InvalidateSessionsRequestDto dto = InvalidateSessionsRequestDto.builder()
                .tokenIds(null)
                .build();
        
        // Act
        Set<ConstraintViolation<InvalidateSessionsRequestDto>> violations = validator.validate(dto);
        
        // Assert
        assertFalse(violations.isEmpty(), "Null tokenIds should cause validation error");
        assertTrue(violations.stream()
                .anyMatch(v -> v.getMessage().contains("tokenIds cannot be null")));
    }
    
    @Test
    void testEmptyTokenIds() {
        // Arrange
        InvalidateSessionsRequestDto dto = InvalidateSessionsRequestDto.builder()
                .tokenIds(Collections.emptyList())
                .build();
        
        // Act
        Set<ConstraintViolation<InvalidateSessionsRequestDto>> violations = validator.validate(dto);
        
        // Assert
        assertFalse(violations.isEmpty(), "Empty tokenIds list should cause validation error");
        assertTrue(violations.stream()
                .anyMatch(v -> v.getMessage().contains("tokenIds cannot be empty")));
    }
    
    @Test
    void testSingleTokenId() {
        // Arrange
        InvalidateSessionsRequestDto dto = InvalidateSessionsRequestDto.builder()
                .tokenIds(Collections.singletonList("single-token"))
                .build();
        
        // Act
        Set<ConstraintViolation<InvalidateSessionsRequestDto>> violations = validator.validate(dto);
        
        // Assert
        assertTrue(violations.isEmpty(), "DTO with single token should be valid");
        assertEquals(1, dto.getTokenIds().size());
    }
    
    @Test
    void testMultipleTokenIds() {
        // Arrange
        final int expectedSize = 5;
        List<String> tokens = Arrays.asList("token1", "token2", "token3", "token4", "token5");
        InvalidateSessionsRequestDto dto = InvalidateSessionsRequestDto.builder()
                .tokenIds(tokens)
                .build();
        
        // Act
        Set<ConstraintViolation<InvalidateSessionsRequestDto>> violations = validator.validate(dto);
        
        // Assert
        assertTrue(violations.isEmpty(), "DTO with multiple tokens should be valid");
        assertEquals(expectedSize, dto.getTokenIds().size());
    }
    
    @Test
    void testEqualsAndHashCode() {
        // Arrange
        InvalidateSessionsRequestDto dto1 = InvalidateSessionsRequestDto.builder()
                .tokenIds(Arrays.asList("token1", "token2"))
                .build();
        
        InvalidateSessionsRequestDto dto2 = InvalidateSessionsRequestDto.builder()
                .tokenIds(Arrays.asList("token1", "token2"))
                .build();
        
        InvalidateSessionsRequestDto dto3 = InvalidateSessionsRequestDto.builder()
                .tokenIds(Arrays.asList("token3", "token4"))
                .build();
        
        // Assert
        assertEquals(dto1, dto2, "DTOs with same data should be equal");
        assertEquals(dto1.hashCode(), dto2.hashCode(), "DTOs with same data should have same hash code");
        assertNotEquals(dto1, dto3, "DTOs with different data should not be equal");
    }
    
    @Test
    void testToString() {
        // Arrange
        InvalidateSessionsRequestDto dto = InvalidateSessionsRequestDto.builder()
                .tokenIds(Arrays.asList("token1", "token2"))
                .build();
        
        // Act
        String toString = dto.toString();
        
        // Assert
        assertNotNull(toString);
        assertTrue(toString.contains("token1") || toString.contains("tokenIds"));
    }
}
