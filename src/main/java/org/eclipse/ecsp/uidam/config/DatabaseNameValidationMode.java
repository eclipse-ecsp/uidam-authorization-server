/*
 *
 *   ******************************************************************************
 *
 *    Copyright (c) 2023-24 Harman International
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *
 *    you may not use this file except in compliance with the License.
 *
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *    See the License for the specific language governing permissions and
 *
 *    limitations under the License.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    *******************************************************************************
 *
 */

package org.eclipse.ecsp.uidam.config;

/**
 * Enum representing different validation modes for database name validation
 * against tenant ID in JDBC URL.
 */
public enum DatabaseNameValidationMode {
    /**
     * No validation - database name is not checked against tenant ID.
     */
    NONE,
    
    /**
     * Database name must exactly equal the tenant ID.
     */
    EQUAL,
    
    /**
     * Database name must start with the tenant ID as a prefix.
     */
    PREFIX,
    
    /**
     * Database name must contain the tenant ID somewhere within it.
     */
    CONTAINS;
    
    /**
     * Parses a string value to the corresponding DatabaseNameValidationMode enum.
     * If the value is null, empty, or invalid, returns EQUAL as the default.
     *
     * @param value the string value to parse
     * @return the corresponding DatabaseNameValidationMode, or EQUAL if invalid
     */
    public static DatabaseNameValidationMode fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            return EQUAL;
        }
        
        try {
            return DatabaseNameValidationMode.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return EQUAL;
        }
    }
}
