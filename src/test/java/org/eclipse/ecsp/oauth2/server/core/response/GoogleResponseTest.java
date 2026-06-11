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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GoogleResponseTest {

    private GoogleResponse googleResponse;

    @BeforeEach
    void setUp() {
        googleResponse = new GoogleResponse();
    }

    @Test
    void testIsSuccess_True() {
        googleResponse.setSuccess(true);
        assertTrue(googleResponse.isSuccess());
    }

    @Test
    void testIsSuccess_False() {
        googleResponse.setSuccess(false);
        assertFalse(googleResponse.isSuccess());
    }

    @Test
    void testChallengeTimeStamp_SetAndGet() {
        String timestamp = "2024-01-15T10:30:00Z";
        googleResponse.setChallengeTimeStamp(timestamp);
        assertEquals(timestamp, googleResponse.getChallengeTimeStamp());
    }

    @Test
    void testChallengeTimeStamp_DefaultNull() {
        assertNull(googleResponse.getChallengeTimeStamp());
    }

    @Test
    void testHostname_SetAndGet() {
        String hostname = "example.com";
        googleResponse.setHostname(hostname);
        assertEquals(hostname, googleResponse.getHostname());
    }

    @Test
    void testHostname_DefaultNull() {
        assertNull(googleResponse.getHostname());
    }

    @Test
    void testScore_SetAndGet() {
        googleResponse.setScore(0.9f);
        assertEquals(0.9f, googleResponse.getScore());
    }

    @Test
    void testScore_Zero() {
        googleResponse.setScore(0.0f);
        assertEquals(0.0f, googleResponse.getScore());
    }

    @Test
    void testScore_One() {
        googleResponse.setScore(1.0f);
        assertEquals(1.0f, googleResponse.getScore());
    }

    @Test
    void testAction_SetAndGet() {
        googleResponse.setAction("LOGIN");
        assertEquals("LOGIN", googleResponse.getAction());
    }

    @Test
    void testAction_DefaultNull() {
        assertNull(googleResponse.getAction());
    }

    @Test
    void testErrorCodes_DefaultNull() {
        assertNull(googleResponse.getErrorCodes());
    }

    @Test
    void testErrorCodes_SetAndGet() {
        GoogleResponse.ErrorCode[] errorCodes = {
            GoogleResponse.ErrorCode.INVALID_RESPONSE,
            GoogleResponse.ErrorCode.TIMEOUT_OR_DUPLICATE
        };
        googleResponse.setErrorCodes(errorCodes);
        assertEquals(2, googleResponse.getErrorCodes().length);
        assertEquals(GoogleResponse.ErrorCode.INVALID_RESPONSE, googleResponse.getErrorCodes()[0]);
    }

    @Test
    void testHasClientError_WithInvalidResponse() {
        googleResponse.setErrorCodes(new GoogleResponse.ErrorCode[]{GoogleResponse.ErrorCode.INVALID_RESPONSE});
        assertTrue(googleResponse.hasClientError());
    }

    @Test
    void testHasClientError_WithMissingResponse() {
        googleResponse.setErrorCodes(new GoogleResponse.ErrorCode[]{GoogleResponse.ErrorCode.MISSING_RESPONSE});
        assertTrue(googleResponse.hasClientError());
    }

    @Test
    void testHasClientError_WithBadRequest() {
        googleResponse.setErrorCodes(new GoogleResponse.ErrorCode[]{GoogleResponse.ErrorCode.BAD_REQUEST});
        assertTrue(googleResponse.hasClientError());
    }

    @Test
    void testHasClientError_WithMissingSecret_ShouldReturnFalse() {
        googleResponse.setErrorCodes(new GoogleResponse.ErrorCode[]{GoogleResponse.ErrorCode.MISSING_SECRET});
        assertFalse(googleResponse.hasClientError());
    }

    @Test
    void testHasClientError_WithInvalidSecret_ShouldReturnFalse() {
        googleResponse.setErrorCodes(new GoogleResponse.ErrorCode[]{GoogleResponse.ErrorCode.INVALID_SECRET});
        assertFalse(googleResponse.hasClientError());
    }

    @Test
    void testHasClientError_WithTimeoutOrDuplicate_ShouldReturnFalse() {
        googleResponse.setErrorCodes(new GoogleResponse.ErrorCode[]{GoogleResponse.ErrorCode.TIMEOUT_OR_DUPLICATE});
        assertFalse(googleResponse.hasClientError());
    }

    @Test
    void testHasClientError_EmptyArray_ShouldReturnFalse() {
        googleResponse.setErrorCodes(new GoogleResponse.ErrorCode[]{});
        assertFalse(googleResponse.hasClientError());
    }

    @Test
    void testHasClientError_NullArray_ShouldReturnFalse() {
        googleResponse.setErrorCodes(null);
        assertFalse(googleResponse.hasClientError());
    }

    @Test
    void testHasClientError_MultipleErrors_WithClientError() {
        googleResponse.setErrorCodes(new GoogleResponse.ErrorCode[]{
            GoogleResponse.ErrorCode.INVALID_SECRET,
            GoogleResponse.ErrorCode.INVALID_RESPONSE
        });
        assertTrue(googleResponse.hasClientError());
    }

    @Test
    void testHasClientError_MultipleErrors_NoClientError() {
        googleResponse.setErrorCodes(new GoogleResponse.ErrorCode[]{
            GoogleResponse.ErrorCode.INVALID_SECRET,
            GoogleResponse.ErrorCode.TIMEOUT_OR_DUPLICATE
        });
        assertFalse(googleResponse.hasClientError());
    }

    @Test
    void testErrorCode_ForValue_MissingInputSecret() {
        GoogleResponse.ErrorCode result = GoogleResponse.ErrorCode.forValue("missing-input-secret");
        assertEquals(GoogleResponse.ErrorCode.MISSING_SECRET, result);
    }

    @Test
    void testErrorCode_ForValue_InvalidInputSecret() {
        GoogleResponse.ErrorCode result = GoogleResponse.ErrorCode.forValue("invalid-input-secret");
        assertEquals(GoogleResponse.ErrorCode.INVALID_SECRET, result);
    }

    @Test
    void testErrorCode_ForValue_MissingInputResponse() {
        GoogleResponse.ErrorCode result = GoogleResponse.ErrorCode.forValue("missing-input-response");
        assertEquals(GoogleResponse.ErrorCode.MISSING_RESPONSE, result);
    }

    @Test
    void testErrorCode_ForValue_InvalidInputResponse() {
        GoogleResponse.ErrorCode result = GoogleResponse.ErrorCode.forValue("invalid-input-response");
        assertEquals(GoogleResponse.ErrorCode.INVALID_RESPONSE, result);
    }

    @Test
    void testErrorCode_ForValue_BadRequest() {
        GoogleResponse.ErrorCode result = GoogleResponse.ErrorCode.forValue("bad-request");
        assertEquals(GoogleResponse.ErrorCode.BAD_REQUEST, result);
    }

    @Test
    void testErrorCode_ForValue_TimeoutOrDuplicate() {
        GoogleResponse.ErrorCode result = GoogleResponse.ErrorCode.forValue("timeout-or-duplicate");
        assertEquals(GoogleResponse.ErrorCode.TIMEOUT_OR_DUPLICATE, result);
    }

    @Test
    void testErrorCode_ForValue_UnknownCode_ReturnsNull() {
        GoogleResponse.ErrorCode result = GoogleResponse.ErrorCode.forValue("unknown-code");
        assertNull(result);
    }

    @Test
    void testErrorCode_ForValue_CaseInsensitive() {
        GoogleResponse.ErrorCode result = GoogleResponse.ErrorCode.forValue("BAD-REQUEST");
        assertEquals(GoogleResponse.ErrorCode.BAD_REQUEST, result);
    }

    @Test
    void testErrorCode_ForValue_MixedCase() {
        GoogleResponse.ErrorCode result = GoogleResponse.ErrorCode.forValue("Missing-Input-Response");
        assertEquals(GoogleResponse.ErrorCode.MISSING_RESPONSE, result);
    }

    @Test
    void testToString_WithAllFieldsSet() {
        googleResponse.setSuccess(true);
        googleResponse.setChallengeTimeStamp("2024-01-15T10:30:00Z");
        googleResponse.setHostname("example.com");
        googleResponse.setScore(0.9f);
        googleResponse.setAction("LOGIN");
        String result = googleResponse.toString();
        assertNotNull(result);
        assertTrue(result.contains("success=true"));
        assertTrue(result.contains("2024-01-15T10:30:00Z"));
        assertTrue(result.contains("example.com"));
        assertTrue(result.contains("LOGIN"));
    }

    @Test
    void testToString_EmptyObject() {
        String result = googleResponse.toString();
        assertNotNull(result);
        assertTrue(result.startsWith("GoogleResponse{"));
    }
}
