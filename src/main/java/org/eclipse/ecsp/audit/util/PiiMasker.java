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

package org.eclipse.ecsp.audit.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * PII Masker Utility - Automatically masks PII fields in JSON data before database storage.
 * 
 * <p>PII fields are masked with "***MASKED***" to comply with privacy regulations.</p>
 *
 * @version 2.0.0
 * @since 1.2.0
 */
@Slf4j
public final class PiiMasker {
    
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String MASK_VALUE = "***MASKED***";
    
    /**
     * List of field names containing PII that should be masked.
     * This list can be extended based on compliance requirements.
     */
    private static final List<String> PII_FIELDS = Arrays.asList(
        "username",
        "email",
        "emailAddress",
        "phoneNumber",
        "phone",
        "ssn",
        "socialSecurityNumber",
        "dob",
        "dateOfBirth",
        "address",
        "firstName",
        "lastName",
        "fullName",
        "accountName",
        "password",
        "token",
        "accessToken",
        "refreshToken",
        "idToken"
    );
    
    private PiiMasker() {
        // Utility class
    }
    
    /**
     * Mask PII fields in a JSON string.
     *
     * @param json JSON string to mask
     * @return masked JSON string, or null if input is null
     */
    public static String maskJson(String json) {
        if (json == null || json.trim().isEmpty()) {
            return null;
        }
        
        try {
            JsonNode rootNode = OBJECT_MAPPER.readTree(json);
            maskNode(rootNode);
            return OBJECT_MAPPER.writeValueAsString(rootNode);
        } catch (JsonProcessingException e) {
            log.error("Failed to mask PII in JSON: {}", e.getMessage());
            return json; // Return original on error
        }
    }
    
    /**
     * Mask PII fields in a Map and convert to JSON string.
     *
     * @param map Map to mask and convert
     * @return masked JSON string, or null if input is null
     */
    public static String maskAndSerialize(Map<String, Object> map) {
        if (map == null || map.isEmpty()) {
            return null;
        }
        
        try {
            JsonNode node = OBJECT_MAPPER.valueToTree(map);
            maskNode(node);
            return OBJECT_MAPPER.writeValueAsString(node);
        } catch (Exception e) {
            log.error("Failed to mask and serialize map: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Recursively mask PII fields in a JSON node.
     *
     * @param node JSON node to mask
     */
    private static void maskNode(JsonNode node) {
        if (node == null || !node.isObject()) {
            return;
        }
        
        ObjectNode objectNode = (ObjectNode) node;
        objectNode.fields().forEachRemaining(entry -> {
            String fieldName = entry.getKey();
            JsonNode value = entry.getValue();
            
            // Check if field should be masked
            if (shouldMask(fieldName)) {
                objectNode.put(fieldName, MASK_VALUE);
            } else if (value.isObject()) {
                // Recursively mask nested objects
                maskNode(value);
            } else if (value.isArray()) {
                // Recursively mask array elements
                value.forEach(PiiMasker::maskNode);
            }
        });
    }
    
    /**
     * Check if a field name should be masked.
     *
     * @param fieldName field name to check
     * @return true if field should be masked
     */
    private static boolean shouldMask(String fieldName) {
        if (fieldName == null) {
            return false;
        }
        
        String lowerFieldName = fieldName.toLowerCase();
        return PII_FIELDS.stream()
            .anyMatch(piiField -> lowerFieldName.contains(piiField.toLowerCase()));
    }
    
    /**
     * Add custom PII field patterns to the masking list.
     * This method is not thread-safe and should be called during application initialization.
     *
     * @param customPiiFields custom field names to mask
     */
    public static void addCustomPiiFields(String... customPiiFields) {
        PII_FIELDS.addAll(Arrays.asList(customPiiFields));
    }
}
