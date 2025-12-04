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
 * PII Masker Utility - Masks PII fields in JSON before database storage.
 * 
 * <p>Masking Strategy (aligned with sp-platform-logger):</p>
 * <ul>
 *   <li><strong>Partial:</strong> Shows last 4 chars for identification 
 *   fields (VIN, username, email, phone)</li>
 *   <li><strong>Full:</strong> Completely masks security credentials 
 *   (password, token, keys)</li>
 * </ul>
 *
 * @version 2.0.0
 * @since 1.2.0
 */
@Slf4j
public final class PiiMasker {
    
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String MASK_VALUE = "***MASKED***";
    private static final String PARTIAL_MASK_PREFIX = "******";
    private static final int PARTIAL_MASK_VISIBLE_CHARS = 4;
    
    // Masking strategy constants for field-specific partial masking
    private static final int EMAIL_MIN_VISIBLE_FIRST = 2;
    private static final int EMAIL_MAX_VISIBLE_FIRST = 3;
    private static final int EMAIL_THRESHOLD_LENGTH = 5;
    private static final int USERNAME_VISIBLE_FIRST = 2;
    private static final int USERNAME_VISIBLE_LAST = 2;
    private static final int USERNAME_MIN_LENGTH = 4;
    private static final int PHONE_VISIBLE_LAST = 4;
    private static final int VIN_VISIBLE_LAST = 4;
    
    /**
     * Fields that should be FULLY masked (no visible characters).
     * These are security-critical credentials that should never be partially visible.
     */
    private static final List<String> FULL_MASK_FIELDS = Arrays.asList(
        "password",
        "pwd",
        "pass",
        "secret",
        "token",
        "accessToken",
        "refreshToken",
        "idToken",
        "apiKey",
        "key",
        "privateKey",
        "publicKey",
        "credential",
        "auth",
        "authorization",
        "sessionId",
        "sessionToken"
    );
    
    /**
     * Fields that should be PARTIALLY masked (show last 4 characters).
     * These fields help with identification/debugging while protecting privacy.
     */
    private static final List<String> PARTIAL_MASK_FIELDS = Arrays.asList(
        // User Identity
        "username",
        "email",
        "emailAddress",
        "accountName",
        
        // Contact Information
        "phoneNumber",
        "phone",
        "mobileNumber",
        
        // Sensitive Personal Data
        "ssn",
        "socialSecurityNumber",
        "nationalId",
        "passportNumber",
        "driverLicense",
        
        // Vehicle Information (VIN)
        "vin",
        "vehicleIdentificationNumber"
    );
    
    /**
     * Fields that should be FULLY masked (complete removal).
     * These are highly sensitive personal data fields.
     */
    private static final List<String> SENSITIVE_PERSONAL_FIELDS = Arrays.asList(
        "firstName",
        "lastName",
        "fullName",
        "displayName",
        "address",
        "streetAddress",
        "city",
        "postalCode",
        "zipCode",
        "dob",
        "dateOfBirth",
        "birthDate"
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
            
            // Determine masking strategy
            if (shouldFullyMask(fieldName)) {
                objectNode.put(fieldName, MASK_VALUE);
            } else if (shouldPartiallyMask(fieldName) && value.isTextual()) {
                String maskedValue = applyPartialMask(fieldName, value.asText());
                objectNode.put(fieldName, maskedValue);
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
     * Apply partial masking to a value based on field type.
     * Uses industry-standard masking strategies for different field types.
     *
     * @param fieldName field name to determine masking strategy
     * @param value original value
     * @return partially masked value
     */
    private static String applyPartialMask(String fieldName, String value) {
        if (value == null || value.isEmpty()) {
            return MASK_VALUE;
        }
        
        String lowerFieldName = fieldName.toLowerCase();
        
        // Email masking: show first 2-3 chars + full domain (te***@example.com)
        if (lowerFieldName.contains("email")) {
            return maskEmail(value);
        }
        
        // Phone masking: show last 4 digits only (******7890)
        if (lowerFieldName.contains("phone") || lowerFieldName.contains("mobile")) {
            return maskPhone(value);
        }
        
        // Username masking: show first 2 + last 2 chars (jo***th)
        if (lowerFieldName.contains("username") || lowerFieldName.contains("accountname")) {
            return maskUsername(value);
        }
        
        // VIN masking: show last 4 chars (******2345)
        if (lowerFieldName.contains("vin") || lowerFieldName.contains("vehicleidentification")) {
            return maskVin(value);
        }
        
        // Default: show last 4 characters for other identification fields
        return maskDefault(value);
    }
    
    /**
     * Mask email address - show first 2-3 characters and full domain.
     * Example: test@example.com → te***@example.com
     *
     * @param email email address to mask
     * @return masked email
     */
    private static String maskEmail(String email) {
        if (!email.contains("@")) {
            return MASK_VALUE;
        }
        
        String[] parts = email.split("@", EMAIL_MIN_VISIBLE_FIRST);
        String localPart = parts[0];
        String domain = parts[1];
        
        if (localPart.length() <= EMAIL_MIN_VISIBLE_FIRST) {
            return MASK_VALUE + "@" + domain;
        }
        
        // Show first 2 chars for short local parts, 3 for longer ones
        int visibleChars = localPart.length() <= EMAIL_THRESHOLD_LENGTH 
            ? EMAIL_MIN_VISIBLE_FIRST : EMAIL_MAX_VISIBLE_FIRST;
        String maskedLocal = localPart.substring(0, visibleChars) + "***";
        
        return maskedLocal + "@" + domain;
    }
    
    /**
     * Mask phone number - show last 4 digits only.
     * Example: (123) 456-7890 → ******7890
     *
     * @param phone phone number to mask
     * @return masked phone
     */
    private static String maskPhone(String phone) {
        // Extract digits only
        String digits = phone.replaceAll("[^0-9]", "");
        
        if (digits.length() < PHONE_VISIBLE_LAST) {
            return MASK_VALUE;
        }
        
        String lastFour = digits.substring(digits.length() - PHONE_VISIBLE_LAST);
        return PARTIAL_MASK_PREFIX + lastFour;
    }
    
    /**
     * Mask username - show first 2 and last 2 characters.
     * Example: johnsmith → jo***th
     *
     * @param username username to mask
     * @return masked username
     */
    private static String maskUsername(String username) {
        if (username.length() <= USERNAME_MIN_LENGTH) {
            return MASK_VALUE;
        }
        
        String first = username.substring(0, USERNAME_VISIBLE_FIRST);
        String last = username.substring(username.length() - USERNAME_VISIBLE_LAST);
        
        return first + "***" + last;
    }
    
    /**
     * Mask VIN - show last 4 characters.
     * Example: ABC12345678 → ******5678
     *
     * @param vin VIN to mask
     * @return masked VIN
     */
    private static String maskVin(String vin) {
        if (vin.length() <= VIN_VISIBLE_LAST) {
            return MASK_VALUE;
        }
        
        String lastFour = vin.substring(vin.length() - VIN_VISIBLE_LAST);
        return PARTIAL_MASK_PREFIX + lastFour;
    }
    
    /**
     * Default partial masking - show last 4 characters.
     * Example: ABC12345678 → ******5678
     *
     * @param value value to mask
     * @return masked value
     */
    private static String maskDefault(String value) {
        if (value.length() <= PARTIAL_MASK_VISIBLE_CHARS) {
            return MASK_VALUE;
        }
        
        String visiblePart = value.substring(value.length() - PARTIAL_MASK_VISIBLE_CHARS);
        return PARTIAL_MASK_PREFIX + visiblePart;
    }
    
    /**
     * Check if a field should be fully masked (no visible characters).
     *
     * @param fieldName field name to check
     * @return true if field should be fully masked
     */
    private static boolean shouldFullyMask(String fieldName) {
        if (fieldName == null) {
            return false;
        }
        
        String lowerFieldName = fieldName.toLowerCase();
        return FULL_MASK_FIELDS.stream()
            .anyMatch(field -> lowerFieldName.contains(field.toLowerCase()))
            || SENSITIVE_PERSONAL_FIELDS.stream()
            .anyMatch(field -> lowerFieldName.contains(field.toLowerCase()));
    }
    
    /**
     * Check if a field should be partially masked (show last 4 characters).
     *
     * @param fieldName field name to check
     * @return true if field should be partially masked
     */
    private static boolean shouldPartiallyMask(String fieldName) {
        if (fieldName == null) {
            return false;
        }
        
        String lowerFieldName = fieldName.toLowerCase();
        return PARTIAL_MASK_FIELDS.stream()
            .anyMatch(field -> lowerFieldName.contains(field.toLowerCase()));
    }
}
