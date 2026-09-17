/*******************************************************************************
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
 *******************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.response.dto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link UserAttributeDto}.
 * Covers HTML input type mapping, textarea/checkbox detection, step attribute,
 * and the new {@code attributeLabel} field.
 */
class UserAttributeDtoTest {

    // -----------------------------------------------------------------------
    // attributeLabel getter / setter
    // -----------------------------------------------------------------------

    @Test
    void getSetAttributeLabel_roundTrip() {
        UserAttributeDto dto = new UserAttributeDto();
        assertNull(dto.getAttributeLabel());
        dto.setAttributeLabel("Company Name");
        assertEquals("Company Name", dto.getAttributeLabel());
    }

    @Test
    void getSetAttributeLabel_emptyString() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setAttributeLabel("");
        assertEquals("", dto.getAttributeLabel());
    }

    @Test
    void getSetAttributeLabel_null_remainsNull() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setAttributeLabel(null);
        assertNull(dto.getAttributeLabel());
    }

    // -----------------------------------------------------------------------
    // getHtmlInputType – null type
    // -----------------------------------------------------------------------

    @Test
    void getHtmlInputType_nullType_returnsText() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(null);
        assertEquals("text", dto.getHtmlInputType());
    }

    // -----------------------------------------------------------------------
    // getHtmlInputType – text family (defaults to "text")
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = { "varchar", "text", "char", "name", "uuid", "unknown_type" })
    void getHtmlInputType_textFamily_returnsText(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertEquals("text", dto.getHtmlInputType());
    }

    // -----------------------------------------------------------------------
    // getHtmlInputType – number family
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {
        "int4", "int8", "int2", "serial", "bigserial", "oid",
        "float4", "float8", "money", "numeric"
    })
    void getHtmlInputType_numberFamily_returnsNumber(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertEquals("number", dto.getHtmlInputType());
    }

    // -----------------------------------------------------------------------
    // getHtmlInputType – boolean family
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = { "bool", "bit" })
    void getHtmlInputType_boolFamily_returnsCheckbox(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertEquals("checkbox", dto.getHtmlInputType());
    }

    // -----------------------------------------------------------------------
    // getHtmlInputType – date/time family
    // -----------------------------------------------------------------------

    @Test
    void getHtmlInputType_date_returnsDate() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType("date");
        assertEquals("date", dto.getHtmlInputType());
    }

    @ParameterizedTest
    @ValueSource(strings = { "time", "timetz" })
    void getHtmlInputType_time_returnsTime(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertEquals("time", dto.getHtmlInputType());
    }

    @Test
    void getHtmlInputType_timestamp_returnsDatetimeLocal() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType("timestamp");
        assertEquals("datetime-local", dto.getHtmlInputType());
    }

    // -----------------------------------------------------------------------
    // getHtmlInputType – case-insensitive
    // -----------------------------------------------------------------------

    @Test
    void getHtmlInputType_upperCaseType_isCaseInsensitive() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType("VARCHAR");
        assertEquals("text", dto.getHtmlInputType());
    }

    @Test
    void getHtmlInputType_mixedCaseInt4_returnsNumber() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType("Int4");
        assertEquals("number", dto.getHtmlInputType());
    }

    // -----------------------------------------------------------------------
    // isTextArea
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = { "json", "jsonb", "JSON", "JSONB" })
    void isTextArea_jsonTypes_returnsTrue(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertTrue(dto.isTextArea());
    }

    @ParameterizedTest
    @ValueSource(strings = { "varchar", "int4", "bool", "text" })
    void isTextArea_nonJsonTypes_returnsFalse(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertFalse(dto.isTextArea());
    }

    @Test
    void isTextArea_nullType_returnsFalse() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(null);
        assertFalse(dto.isTextArea());
    }

    // -----------------------------------------------------------------------
    // isCheckbox
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = { "bool", "bit", "BOOL", "BIT" })
    void isCheckbox_boolTypes_returnsTrue(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertTrue(dto.isCheckbox());
    }

    @ParameterizedTest
    @ValueSource(strings = { "varchar", "int4", "json", "text" })
    void isCheckbox_nonBoolTypes_returnsFalse(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertFalse(dto.isCheckbox());
    }

    @Test
    void isCheckbox_nullType_returnsFalse() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(null);
        assertFalse(dto.isCheckbox());
    }

    // -----------------------------------------------------------------------
    // getHtmlStep
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = { "float4", "float8", "money", "numeric" })
    void getHtmlStep_floatTypes_returnsAny(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertEquals("any", dto.getHtmlStep());
    }

    @ParameterizedTest
    @ValueSource(strings = { "int4", "int8", "varchar", "bool", "date" })
    void getHtmlStep_nonFloatTypes_returnsNull(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertNull(dto.getHtmlStep());
    }

    @Test
    void getHtmlStep_nullType_returnsNull() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(null);
        assertNull(dto.getHtmlStep());
    }

    // -----------------------------------------------------------------------
    // Basic getter/setter for other fields
    // -----------------------------------------------------------------------

    @Test
    void getSetName_roundTrip() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setName("nickName");
        assertEquals("nickName", dto.getName());
    }

    @Test
    void getSetMandatory_roundTrip() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setMandatory(true);
        assertTrue(dto.getMandatory());
        dto.setMandatory(false);
        assertFalse(dto.getMandatory());
    }

    @Test
    void getSetDynamicAttribute_roundTrip() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setDynamicAttribute(false);
        assertFalse(dto.getDynamicAttribute());
    }

    @Test
    void getSetRegex_roundTrip() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setRegex("[a-z]+");
        assertEquals("[a-z]+", dto.getRegex());
    }

    // -----------------------------------------------------------------------
    // needsFloatingLabel
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = { "varchar", "text", "char", "uuid", "unknown_type" })
    void needsFloatingLabel_textFamily_returnsTrue(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertTrue(dto.needsFloatingLabel());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "int4", "int8", "int2", "serial", "bigserial", "oid",
        "float4", "float8", "money", "numeric"
    })
    void needsFloatingLabel_numberFamily_returnsTrue(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertTrue(dto.needsFloatingLabel());
    }

    @ParameterizedTest
    @ValueSource(strings = { "json", "jsonb", "JSON", "JSONB" })
    void needsFloatingLabel_textAreaTypes_returnsTrue(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertTrue(dto.needsFloatingLabel());
    }

    @Test
    void needsFloatingLabel_nullType_returnsTrue() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(null);
        assertTrue(dto.needsFloatingLabel());
    }

    @Test
    void needsFloatingLabel_date_returnsFalse() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType("date");
        assertFalse(dto.needsFloatingLabel());
    }

    @ParameterizedTest
    @ValueSource(strings = { "time", "timetz" })
    void needsFloatingLabel_timeTypes_returnsFalse(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertFalse(dto.needsFloatingLabel());
    }

    @Test
    void needsFloatingLabel_timestamp_returnsFalse() {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType("timestamp");
        assertFalse(dto.needsFloatingLabel());
    }

    @ParameterizedTest
    @ValueSource(strings = { "bool", "bit", "BOOL", "BIT" })
    void needsFloatingLabel_checkboxTypes_returnsFalse(String pgType) {
        UserAttributeDto dto = new UserAttributeDto();
        dto.setType(pgType);
        assertFalse(dto.needsFloatingLabel());
    }
}
