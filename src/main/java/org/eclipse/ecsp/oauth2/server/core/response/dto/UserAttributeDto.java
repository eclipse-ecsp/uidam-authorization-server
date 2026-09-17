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

package org.eclipse.ecsp.oauth2.server.core.response.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;
import java.util.Map;

/**
 * DTO representing a single user attribute definition fetched from user-management.
 * Used to drive the additional-attributes section of the self sign-up form.
 */
@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserAttributeDto {

    private static final String CONSTANT_STRING_NUMBER = "number";
    
    private static final Map<String, String> HTML_INPUT_TYPE_MAP = Map.ofEntries(
            Map.entry("bool", "checkbox"),
            Map.entry("bit", "checkbox"),
            Map.entry("int4", CONSTANT_STRING_NUMBER),
            Map.entry("int8", CONSTANT_STRING_NUMBER),
            Map.entry("int2", CONSTANT_STRING_NUMBER),
            Map.entry("serial", CONSTANT_STRING_NUMBER),
            Map.entry("bigserial", CONSTANT_STRING_NUMBER),
            Map.entry("oid", CONSTANT_STRING_NUMBER),
            Map.entry("float4", CONSTANT_STRING_NUMBER),
            Map.entry("float8", CONSTANT_STRING_NUMBER),
            Map.entry("money", CONSTANT_STRING_NUMBER),
            Map.entry("numeric", CONSTANT_STRING_NUMBER),
            Map.entry("date", "date"),
            Map.entry("time", "time"),
            Map.entry("timetz", "time"),
            Map.entry("timestamp", "datetime-local")
    );
    private static final Map<String, String> HTML_STEP_MAP = Map.of(
            "float4", "any",
            "float8", "any",
            "money", "any",
            "numeric", "any"
    );

    private String name;
    private Boolean mandatory;
    private Boolean dynamicAttribute;
    private String type;
    private String regex;
    private String attributeLabel;

    /**
     * Returns the HTML {@code input} type that best represents this attribute's data type.
     * Maps PostgreSQL type names (as stored in {@code user_attributes.types}) to HTML input types.
     *
     * @return HTML input type string, e.g. {@code "text"}, {@code "number"}, {@code "date"}
     */
    public String getHtmlInputType() {
        if (type == null) {
            return "text";
        }
        return HTML_INPUT_TYPE_MAP.getOrDefault(type.toLowerCase(), "text");
    }

    /**
     * Returns {@code true} when this attribute should be rendered as a {@code <textarea>}
     * rather than a regular input (used for {@code json} and {@code jsonb} types).
     *
     * @return {@code true} for json/jsonb types
     */
    public boolean isTextArea() {
        return type != null
                && (type.equalsIgnoreCase("json") || type.equalsIgnoreCase("jsonb"));
    }

    /**
     * Returns {@code true} when this attribute should be rendered as a checkbox
     * ({@code bool} / {@code bit} types).
     *
     * @return {@code true} for bool/bit types
     */
    public boolean isCheckbox() {
        return type != null
                && (type.equalsIgnoreCase("bool") || type.equalsIgnoreCase("bit"));
    }

    /**
     * Returns the value for the HTML {@code step} attribute for decimal/float types,
     * or {@code null} for integer and text types (Thymeleaf omits null attributes).
     *
     * @return {@code "any"} for float/numeric types, {@code null} otherwise
     */
    public String getHtmlStep() {
        if (type == null) { 
            return null;
        }
        return HTML_STEP_MAP.get(type.toLowerCase());
    }

    /**
     * Returns {@code true} for input types where the floating-label animation is
     * meaningful (placeholder text is displayed and disappears on input).
     * For date, time, datetime-local, and checkbox types the placeholder attribute
     * is ignored by browsers, so a static always-visible label must be used instead.
     *
     * @return {@code true} for text and number HTML input types, and for textareas
     */
    public boolean needsFloatingLabel() {
        String inputType = getHtmlInputType();
        return isTextArea() || "text".equals(inputType) || CONSTANT_STRING_NUMBER.equals(inputType);
    }
}
