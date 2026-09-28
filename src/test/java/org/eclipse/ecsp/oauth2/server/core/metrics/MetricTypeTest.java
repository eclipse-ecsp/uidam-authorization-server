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

package org.eclipse.ecsp.oauth2.server.core.metrics;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link MetricType}.
 *
 * @since 1.1.1
 */
// CHECKSTYLE.OFF: MatchXpath
class MetricTypeTest {
    
    @Test
    void testEnumValues() {
        MetricType[] values = MetricType.values();
        
        assertNotNull(values);
        assertTrue(values.length > 0);
        
        // Test specific enum constants exist
        assertNotNull(MetricType.TOTAL_LOGIN_ATTEMPTS);
        assertNotNull(MetricType.SUCCESS_LOGIN_ATTEMPTS);
        assertNotNull(MetricType.FAILURE_LOGIN_ATTEMPTS);
        assertNotNull(MetricType.RBAC_SCOPE_MAPPING_SUCCESS);
        assertNotNull(MetricType.RBAC_SCOPE_MAPPING_FAILURE);
    }
    
    @Test
    void testGetMetricName() {
        assertEquals("total.login.attempts", MetricType.TOTAL_LOGIN_ATTEMPTS.getMetricName());
        assertEquals("success.login.attempts", MetricType.SUCCESS_LOGIN_ATTEMPTS.getMetricName());
        assertEquals("failure.login.attempts", MetricType.FAILURE_LOGIN_ATTEMPTS.getMetricName());
    }
    
    @Test
    void testGetDescription() {
        assertEquals("Total number of login attempts", MetricType.TOTAL_LOGIN_ATTEMPTS.getDescription());
        assertEquals("Total number of successful login attempts", 
                     MetricType.SUCCESS_LOGIN_ATTEMPTS.getDescription());
        assertEquals("Total number of failed login attempts", 
                     MetricType.FAILURE_LOGIN_ATTEMPTS.getDescription());
    }
    
    @Test
    void testFromMetricNameWithValidName() {
        assertEquals(MetricType.TOTAL_LOGIN_ATTEMPTS, 
                     MetricType.fromMetricName("total.login.attempts"));
        assertEquals(MetricType.SUCCESS_LOGIN_ATTEMPTS, 
                     MetricType.fromMetricName("success.login.attempts"));
        assertEquals(MetricType.FAILURE_LOGIN_ATTEMPTS, 
                     MetricType.fromMetricName("failure.login.attempts"));
    }
    
    @Test
    void testFromMetricNameWithInvalidName() {
        assertNull(MetricType.fromMetricName("invalid.metric.name"));
        assertNull(MetricType.fromMetricName(""));
        assertNull(MetricType.fromMetricName("unknown"));
    }
    
    @Test
    void testFromMetricNameWithNull() {
        assertNull(MetricType.fromMetricName(null));
    }
    
    @Test
    void testAllEnumConstantsHaveValidProperties() {
        for (MetricType type : MetricType.values()) {
            assertNotNull(type.getMetricName(), "Metric name should not be null for " + type);
            assertNotNull(type.getDescription(), "Description should not be null for " + type);
            assertFalse(type.getMetricName().isEmpty(), "Metric name should not be empty for " + type);
            assertFalse(type.getDescription().isEmpty(), "Description should not be empty for " + type);
        }
    }
    
    @Test
    void testUniqueMetricNames() {
        MetricType[] values = MetricType.values();
        
        for (int i = 0; i < values.length; i++) {
            for (int j = i + 1; j < values.length; j++) {
                assertNotEquals(values[i].getMetricName(), values[j].getMetricName(),
                               "Metric names should be unique: " + values[i] + " vs " + values[j]);
            }
        }
    }
    
    @Test
    void testFromMetricNameIsConsistent() {
        for (MetricType type : MetricType.values()) {
            assertEquals(type, MetricType.fromMetricName(type.getMetricName()),
                        "fromMetricName should return the same enum constant for " + type);
        }
    }
}
// CHECKSTYLE.ON: MatchXpath