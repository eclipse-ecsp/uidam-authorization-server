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

package org.eclipse.ecsp.oauth2.server.core.response;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for BaseResponse.
 */
class BaseResponseTest {

    private static final int TEST_NUMBER = 123;

    @Test
    void testNoArgsConstructor() {
        BaseResponse response = new BaseResponse();
        
        assertThat(response).isNotNull();
        assertThat(response.getCode()).isNull();
        assertThat(response.getMessage()).isNull();
        assertThat(response.getData()).isNull();
        assertThat(response.getHttpStatus()).isNull();
    }

    @Test
    void testAllArgsConstructor() {
        String code = "200";
        String message = "Success";
        Object data = new Object();
        HttpStatus status = HttpStatus.OK;
        
        BaseResponse response = new BaseResponse(code, message, data, status);
        
        assertThat(response.getCode()).isEqualTo(code);
        assertThat(response.getMessage()).isEqualTo(message);
        assertThat(response.getData()).isEqualTo(data);
        assertThat(response.getHttpStatus()).isEqualTo(status);
    }

    @Test
    void testSettersAndGetters() {
        BaseResponse response = new BaseResponse();
        String code = "404";
        String message = "Not Found";
        Object data = "test data";
        HttpStatus status = HttpStatus.NOT_FOUND;
        
        response.setCode(code);
        response.setMessage(message);
        response.setData(data);
        response.setHttpStatus(status);
        
        assertThat(response.getCode()).isEqualTo(code);
        assertThat(response.getMessage()).isEqualTo(message);
        assertThat(response.getData()).isEqualTo(data);
        assertThat(response.getHttpStatus()).isEqualTo(status);
    }

    @Test
    void testSetCodeGetter() {
        BaseResponse response = new BaseResponse();
        String code = "500";
        
        response.setCode(code);
        
        assertThat(response.getCode()).isEqualTo(code);
    }

    @Test
    void testSetMessageGetter() {
        BaseResponse response = new BaseResponse();
        String message = "Internal Server Error";
        
        response.setMessage(message);
        
        assertThat(response.getMessage()).isEqualTo(message);
    }

    @Test
    void testSetDataGetter() {
        BaseResponse response = new BaseResponse();
        Object data = new TestData("test");
        
        response.setData(data);
        
        assertThat(response.getData()).isEqualTo(data);
    }

    @Test
    void testSetHttpStatusGetter() {
        BaseResponse response = new BaseResponse();
        HttpStatus status = HttpStatus.CREATED;
        
        response.setHttpStatus(status);
        
        assertThat(response.getHttpStatus()).isEqualTo(status);
    }

    @Test
    void testWithNullValues() {
        BaseResponse response = new BaseResponse(null, null, null, null);
        
        assertThat(response.getCode()).isNull();
        assertThat(response.getMessage()).isNull();
        assertThat(response.getData()).isNull();
        assertThat(response.getHttpStatus()).isNull();
    }

    @Test
    void testWithEmptyStringValues() {
        BaseResponse response = new BaseResponse("", "", new Object(), HttpStatus.OK);
        
        assertThat(response.getCode()).isEmpty();
        assertThat(response.getMessage()).isEmpty();
    }

    @Test
    void testWithDifferentDataTypes() {
        BaseResponse response = new BaseResponse();
        
        // Test with String
        response.setData("string data");
        assertThat(response.getData()).isInstanceOf(String.class);
        
        // Test with Integer
        response.setData(TEST_NUMBER);
        assertThat(response.getData()).isInstanceOf(Integer.class);
        
        // Test with custom object
        TestData testData = new TestData("test");
        response.setData(testData);
        assertThat(response.getData()).isInstanceOf(TestData.class);
    }

    // Helper class for testing
    private static class TestData {
        private final String value;
        
        TestData(String value) {
            this.value = value;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            TestData testData = (TestData) o;
            return value != null ? value.equals(testData.value) : testData.value == null;
        }
        
        @Override
        public int hashCode() {
            return value.hashCode();
        }
    }
}
