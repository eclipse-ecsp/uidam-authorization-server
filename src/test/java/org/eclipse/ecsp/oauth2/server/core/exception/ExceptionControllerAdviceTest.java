/*******************************************************************************
 * Copyright (c) 2024 Harman International
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
 ******************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.exception;

import org.eclipse.ecsp.oauth2.server.core.common.CustomOauth2TokenGenErrorCodes;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.CaptchaProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.response.BaseRepresentation;
import org.eclipse.ecsp.oauth2.server.core.response.BaseResponse;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.ModelAndView;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test class for ExceptionControllerAdvice.
 * Tests all exception handlers and their response formats.
 */
@ExtendWith(MockitoExtension.class)
class ExceptionControllerAdviceTest {

    @Mock
    private TenantConfigurationService tenantConfigurationService;

    @Mock
    private TenantProperties tenantProperties;

    @Mock
    private CaptchaProperties captchaProperties;

    private static final int BAD_REQUEST_STATUS = 400;
    private static final int UNAUTHORIZED_STATUS = 401;

    private ExceptionControllerAdvice exceptionControllerAdvice;

    @BeforeEach
    void setUp() throws NoSuchFieldException, IllegalAccessException {
        exceptionControllerAdvice = new ExceptionControllerAdvice(tenantConfigurationService);
        
        // Use reflection to set the private field for testing
        Field field = ExceptionControllerAdvice.class.getDeclaredField("tenantConfigurationService");
        field.setAccessible(true);
        field.set(exceptionControllerAdvice, tenantConfigurationService);
    }

    @Test
    void testConstructor() {
        assertNotNull(exceptionControllerAdvice);
    }

    @Test
    void testMethodArgumentTypeMismatchExceptionHandler() {
        MethodArgumentTypeMismatchException exception = new MethodArgumentTypeMismatchException(
                "testValue", String.class, "testParam", null, new RuntimeException("test error"));

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testHttpMediaTypeNotSupportedExceptionHandler() {
        HttpMediaTypeNotSupportedException exception = new HttpMediaTypeNotSupportedException("test message");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testHttpMessageNotReadableExceptionHandler() {
        RuntimeException cause = new RuntimeException("test IO exception");
        HttpMessageNotReadableException exception = new HttpMessageNotReadableException(
                "test message", cause, null);

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testHttpMessageConversionExceptionHandler() {
        HttpMessageConversionException exception = new HttpMessageConversionException("test message");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testIllegalArgumentExceptionHandler() {
        IllegalArgumentException exception = new IllegalArgumentException("test message");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testHttpMediaTypeNotAcceptableExceptionHandler() {
        HttpMediaTypeNotAcceptableException exception = new HttpMediaTypeNotAcceptableException("test message");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testHttpRequestMethodNotSupportedExceptionHandler() {
        HttpRequestMethodNotSupportedException exception = new HttpRequestMethodNotSupportedException("POST");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testMultipartExceptionHandler() {
        MultipartException exception = new MultipartException("test message");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testMissingServletRequestPartExceptionHandler() {
        MissingServletRequestPartException exception = new MissingServletRequestPartException("testPart");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testIllegalStateExceptionHandler() {
        IllegalStateException exception = new IllegalStateException("test message");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_GATEWAY, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testResourceAccessExceptionHandler() {
        ResourceAccessException exception = new ResourceAccessException("test message");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_GATEWAY, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testGeneralExceptionHandler() {
        Exception exception = new Exception("test message");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void testMissingRequestHeaderExceptionHandler() {
        // Use proper constructor: MissingRequestHeaderException(String headerName, MethodParameter parameter)
        // For test purposes, we can use a mock MethodParameter or create one
        MethodParameter mockParameter = mock(MethodParameter.class);
        lenient().when(mockParameter.getNestedParameterType()).thenReturn((Class) String.class);
        MissingRequestHeaderException exception = new MissingRequestHeaderException("testHeader", mockParameter);

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
        assertEquals("testHeader", exception.getHeaderName());
    }

    @Test
    void testKeyGenerationExceptionHandler() {
        KeyGenerationException exception = new KeyGenerationException(new RuntimeException("test key error"));

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testRecordAlreadyExistsExceptionHandler() {
        RecordAlreadyExistsException exception = new RecordAlreadyExistsException("test record");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testPatternMismatchExceptionHandler() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getCaptcha()).thenReturn(captchaProperties);
        when(captchaProperties.getRecaptchaKeySite()).thenReturn("test-site-key");

        ModelAndView modelAndView = exceptionControllerAdvice.patternMismatchException();

        assertNotNull(modelAndView);
        assertEquals("recovery/forgot-password", modelAndView.getViewName());
        assertTrue(modelAndView.getModel().containsKey("error"));
        assertTrue(modelAndView.getModel().containsKey("isCaptchaFieldEnabled"));
        assertTrue(modelAndView.getModel().containsKey("captchaSite"));
        assertEquals("test-site-key", modelAndView.getModel().get("captchaSite"));

        verify(tenantConfigurationService).getTenantProperties();
        verify(tenantProperties).getCaptcha();
        verify(captchaProperties).getRecaptchaKeySite();
    }

    @Test
    void testCustomOauth2AuthorizationExceptionHandler() throws NoSuchMethodException, IllegalAccessException, 
            java.lang.reflect.InvocationTargetException {
        // Create mock error codes
        CustomOauth2TokenGenErrorCodes mockErrorCode = mock(CustomOauth2TokenGenErrorCodes.class);
        when(mockErrorCode.getCode()).thenReturn("error-code");
        when(mockErrorCode.getDescription()).thenReturn("test error message");
        when(mockErrorCode.getStatus()).thenReturn(BAD_REQUEST_STATUS);

        CustomOauth2AuthorizationException exception = new CustomOauth2AuthorizationException(mockErrorCode);

        // Use reflection to access the private method
        java.lang.reflect.Method method = ExceptionControllerAdvice.class
                .getDeclaredMethod("customExceptionHandler", 
                        CustomOauth2AuthorizationException.class);
        method.setAccessible(true);
        @SuppressWarnings("unchecked")
        ResponseEntity<BaseResponse> response = (ResponseEntity<BaseResponse>) method
                .invoke(exceptionControllerAdvice, exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("error-code", response.getBody().getCode());
        assertEquals("test error message", response.getBody().getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, response.getBody().getHttpStatus());
    }

    @Test
    void testCustomOauth2AuthorizationExceptionHandlerWithDifferentStatusCode() throws NoSuchMethodException, 
            IllegalAccessException, java.lang.reflect.InvocationTargetException {
        // Create mock error codes
        CustomOauth2TokenGenErrorCodes mockErrorCode = mock(CustomOauth2TokenGenErrorCodes.class);
        when(mockErrorCode.getCode()).thenReturn("auth-error");
        when(mockErrorCode.getDescription()).thenReturn("unauthorized access");
        when(mockErrorCode.getStatus()).thenReturn(UNAUTHORIZED_STATUS);

        CustomOauth2AuthorizationException exception = new CustomOauth2AuthorizationException(mockErrorCode);

        // Use reflection to access the private method
        java.lang.reflect.Method method = ExceptionControllerAdvice.class
                .getDeclaredMethod("customExceptionHandler", 
                        CustomOauth2AuthorizationException.class);
        method.setAccessible(true);
        @SuppressWarnings("unchecked")
        ResponseEntity<BaseResponse> response = (ResponseEntity<BaseResponse>) method
                .invoke(exceptionControllerAdvice, exception);

        assertNotNull(response);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("auth-error", response.getBody().getCode());
        assertEquals("unauthorized access", response.getBody().getMessage());
        assertEquals(HttpStatus.UNAUTHORIZED, response.getBody().getHttpStatus());
    }

    @Test
    void testPatternMismatchExceptionHandlerWithNullCaptcha() {
        when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        when(tenantProperties.getCaptcha()).thenReturn(null);

        assertThrows(NullPointerException.class, () -> {
            exceptionControllerAdvice.patternMismatchException();
        });

        verify(tenantConfigurationService).getTenantProperties();
        verify(tenantProperties).getCaptcha();
    }

    @Test
    void testMultipleExceptionTypesHandling() {
        // Test that different exception types get different handling
        Exception generalException = new Exception("general error");
        IllegalArgumentException illegalArgException = new IllegalArgumentException("illegal arg");
        IllegalStateException illegalStateException = new IllegalStateException("illegal state");

        ResponseEntity<BaseRepresentation> generalResponse = 
                exceptionControllerAdvice.exceptionHandler(generalException);
        ResponseEntity<BaseRepresentation> illegalArgResponse = 
                exceptionControllerAdvice.exceptionHandler(illegalArgException);
        ResponseEntity<BaseRepresentation> illegalStateResponse = 
                exceptionControllerAdvice.exceptionHandler(illegalStateException);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, generalResponse.getStatusCode());
        assertEquals(HttpStatus.BAD_REQUEST, illegalArgResponse.getStatusCode());
        assertEquals(HttpStatus.BAD_GATEWAY, illegalStateResponse.getStatusCode());
    }

    @Test
    void testResponseMessageContent() {
        IllegalArgumentException exception = new IllegalArgumentException("test message");

        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response.getBody());
        assertNotNull(response.getBody().getMessages());
        assertFalse(response.getBody().getMessages().isEmpty());
        // Verify the response contains appropriate error message structure
        assertTrue(response.getBody().getMessages().get(0).getKey() != null 
                   || response.getBody().getMessages().get(0).getParameters() != null);
    }

    @Test
    void testTenantResolutionExceptionHandler() {
        TenantResolutionException exception = new TenantResolutionException("Tenant not found");

        // TenantResolutionException extends UidamApplicationException extends RuntimeException
        // So it gets handled by the RuntimeException handler which returns BAD_GATEWAY
        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_GATEWAY, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testUidamApplicationExceptionHandler() {
        UidamApplicationException exception = new UidamApplicationException("Application error");

        // UidamApplicationException extends RuntimeException 
        // So it gets handled by the RuntimeException handler which returns BAD_GATEWAY
        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_GATEWAY, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testReCaptchaInvalidExceptionHandler() {
        ReCaptchaInvalidException exception = new ReCaptchaInvalidException("Invalid captcha");

        // ReCaptchaInvalidException extends RuntimeException 
        // So it gets handled by the RuntimeException handler which returns BAD_GATEWAY
        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_GATEWAY, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testReCaptchaUnavailableExceptionHandler() {
        ReCaptchaUnavailableException exception = new ReCaptchaUnavailableException("Captcha service unavailable");

        // ReCaptchaUnavailableException extends RuntimeException 
        // So it gets handled by the RuntimeException handler which returns BAD_GATEWAY
        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_GATEWAY, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }

    @Test
    void testPasswordRecoveryExceptionHandler() {
        PasswordRecoveryException exception = new PasswordRecoveryException("Recovery failed");

        // PasswordRecoveryException extends RuntimeException 
        // So it gets handled by the RuntimeException handler which returns BAD_GATEWAY
        ResponseEntity<BaseRepresentation> response = exceptionControllerAdvice.exceptionHandler(exception);

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_GATEWAY, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse(response.getBody().getMessages().isEmpty());
    }
}
