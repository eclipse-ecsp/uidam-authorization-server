/********************************************************************************
 * Copyright (c) 2023-24 Harman International 
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at 
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0  
 *  
 * <p> Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.exception;

import org.eclipse.ecsp.oauth2.server.core.common.constants.ResponseMessages;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.response.BaseRepresentation;
import org.eclipse.ecsp.oauth2.server.core.response.BaseResponse;
import org.eclipse.ecsp.oauth2.server.core.response.ResponseMessage;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.ModelAndView;

import java.util.ArrayList;
import java.util.List;


import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.RECORD_ALREADY_EXISTS_ERROR_MESSAGE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.RECOVERY_FORGOT_PASSWORD;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ACC_NAME_FORMAT_ERROR;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_FIELD_ENABLED;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CAPTCHA_SITE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ERROR_LITERAL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.TRUE;

/**
 * The ExceptionControllerAdvice class is a central point for exception handling.
 * This class contains methods that handle various types of exceptions that can occur during the execution of the
 * application.
 */
@ControllerAdvice
public class ExceptionControllerAdvice {
    private static final Logger LOGGER = LoggerFactory.getLogger(ExceptionControllerAdvice.class);

    private TenantConfigurationService tenantConfigurationService;

    /**
     * Constructor for ExceptionControllerAdvice.
     * This constructor is used to initialize the tenantConfigurationService field.
     *
     * @param tenantConfigurationService the service used to fetch tenant properties
     */
    public ExceptionControllerAdvice(TenantConfigurationService tenantConfigurationService) {
        this.tenantConfigurationService = tenantConfigurationService;
    }

    /**
     * This method handles MethodArgumentTypeMismatchException.
     * This exception occurs when the type of a path variable does not match the expected type.
     * For example, if the application expects an integer and receives a string.
     * This exception does not represent business logic, therefore it returns a status code of 400 (Bad Request).
     *
     * @param e the exception to handle
     * @return a ResponseEntity containing a BaseRepresentation of the error
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(MethodArgumentTypeMismatchException e) {
        return getResourceNotFoundResponse(e);
    }

    /**
     * This method handles HttpMediaTypeNotSupportedException.
     * This exception occurs when the content type is not supported by the API. For example, if the client sends a
     * text/plain request to an endpoint that only accepts application/json.
     * This exception does not represent business logic, therefore it returns a status code of 400 (Bad Request).
     *
     * @param e the HttpMediaTypeNotSupportedException to handle
     * @return a ResponseEntity containing a BaseRepresentation of the error
     */
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(HttpMediaTypeNotSupportedException e) {
        return getBadRequestResponse(e);
    }

    /**
     * This method handles HttpMessageNotReadableException.
     * This exception occurs when the payload that is passed:
     * - is not a valid json
     * - when the field is unknown
     * - when sent type value doesn't match the requested (String instead of Integer)
     * This exception does not represent business logic, therefore it returns a status code of 400 (Bad Request).
     *
     * @param e the HttpMessageNotReadableException to handle
     * @return a ResponseEntity containing a BaseRepresentation of the error
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(HttpMessageNotReadableException e) {
        return getBadRequestResponse(e);
    }

    /**
     * This method handles HttpMessageConversionException.
     * This exception occurs when there is an issue with converting the HTTP message.
     * This could happen when the application tries to convert a given JSON to an object that doesn't match.
     *
     * @param e the HttpMessageConversionException to handle
     * @return a ResponseEntity containing a BaseRepresentation of the error
     */
    @ExceptionHandler(HttpMessageConversionException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(HttpMessageConversionException e) {
        return getBadRequestResponse(e);
    }

    /**
     * This method handles IllegalArgumentException.
     * This exception occurs when a method has been passed an illegal or inappropriate argument.
     *
     * @param e the IllegalArgumentException to handle
     * @return a ResponseEntity containing a BaseRepresentation of the error
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(IllegalArgumentException e) {
        return getBadRequestResponse(e);
    }

    /**
     * This method handles HttpMediaTypeNotAcceptableException.
     * This exception occurs when the given media type is not acceptable according to the API.
     * For example, if the client sends a request with an 'Accept' header that the server cannot satisfy.
     * This exception does not represent business logic, therefore it returns a status code of 400 (Bad Request).
     *
     * @param e the HttpMediaTypeNotAcceptableException to handle
     * @return a ResponseEntity containing a BaseRepresentation of the error
     */
    @ExceptionHandler(HttpMediaTypeNotAcceptableException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(HttpMediaTypeNotAcceptableException e) {
        return getBadRequestResponse(e);
    }

    /**
     * This method handles HttpRequestMethodNotSupportedException.
     * This exception occurs when the HTTP method sent by the client is not supported by the server.
     * For example, if the client sends a POST request to an endpoint that only accepts GET requests.
     * This exception does not represent business logic, therefore it returns a status code of 400 (Bad Request).
     *
     * @param e the HttpRequestMethodNotSupportedException to handle
     * @return a ResponseEntity containing a BaseRepresentation of the error
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(HttpRequestMethodNotSupportedException e) {
        return getBadRequestResponse(e);
    }

    /**
     * This method handles MultipartException.
     * This exception occurs when the uploaded file in the request exceeds the maximum size.
     * This exception does not represent business logic, therefore it returns a status code of 400 (Bad Request).
     *
     * @param e the MultipartException to handle
     * @return a ResponseEntity containing a BaseRepresentation of the error
     */
    @ExceptionHandler(MultipartException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(MultipartException e) {
        return getBadRequestResponse(e);
    }

    /**
     * This method handles MissingServletRequestPartException.
     * This exception occurs when a part of a "multipart/form-data" request, identified by name, could not be found.
     * This could happen when the client sends a multipart request without one of the expected parts.
     * This exception does not represent business logic, therefore it returns a status code of 400 (Bad Request).
     *
     * @param e the MissingServletRequestPartException to handle
     * @return a ResponseEntity containing a BaseRepresentation of the error
     */
    @ExceptionHandler(MissingServletRequestPartException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(MissingServletRequestPartException e) {
        return getBadRequestResponse(e);
    }

    /**
     * This method handles RuntimeException.
     * IllegalStateException for illegal characters or switched from IllegalArgumentException when configuration is
     * still with placeholder
     * ResourceAccessException for not a valid hostname.
     * The method creates a BaseRepresentation of the error with a "Bad Gateway" message.
     * The method then returns a ResponseEntity with the BaseRepresentation and a HTTP status code of 502 (Bad Gateway).
     *
     * @param e the RuntimeException to handle
     * @return a ResponseEntity containing a BaseRepresentation of the "Bad Gateway" error
     */
    @ExceptionHandler({IllegalStateException.class, ResourceAccessException.class})
    public ResponseEntity<BaseRepresentation> exceptionHandler(RuntimeException e) {
        LOGGER.error("Failed to access resource ", e);
        ResponseMessage errorResponse = new ResponseMessage(ResponseMessages.BAD_GATEWAY);
        BaseRepresentation baseRepresentation = new BaseRepresentation();
        baseRepresentation.addMessage(errorResponse);
        return new ResponseEntity<>(baseRepresentation, HttpStatus.BAD_GATEWAY);
    }

    /**
     * This method handles general exceptions.
     * This is a catch-all method for exceptions that are not caught by other specific exception handlers.
     * The method creates a BaseRepresentation of the error with an "Internal Server Error" message.
     * The method then returns a ResponseEntity with the BaseRepresentation and a HTTP status code of 500
     * (Internal Server Error).
     *
     * @param e the general Exception to handle
     * @return a ResponseEntity containing a BaseRepresentation of the "Internal Server Error"
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(Exception e) {
        LOGGER.error("Internal server error: ", e);
        ResponseMessage errorResponse = new ResponseMessage(ResponseMessages.INTERNAL_ERROR);
        BaseRepresentation baseRepresentation = new BaseRepresentation();
        baseRepresentation.addMessage(errorResponse);
        return new ResponseEntity<>(baseRepresentation, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * This method handles MissingRequestHeaderException.
     * MissingRequestHeaderException is thrown when a request header expected in the method parameters of an
     * RequestMapping method is not present.
     * This could happen when the client sends a request without a required header.
     * The method creates a BaseRepresentation of the error with a "Missing Request Header" message.
     * The method then returns a ResponseEntity with the BaseRepresentation and a HTTP status code of 400 (Bad Request).
     *
     * @param e the MissingRequestHeaderException to handle
     * @return a ResponseEntity containing a BaseRepresentation of the "Missing Request Header" error
     */
    @ExceptionHandler(MissingRequestHeaderException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(MissingRequestHeaderException e) {
        LOGGER.error(e.getMessage(), e);
        String missingHeadername = e.getHeaderName();
        List<ResponseMessage> responseMessages = new ArrayList<>();
        ResponseMessage rm = new ResponseMessage(ResponseMessages.MISSING_REQUEST_HEADER, missingHeadername);
        responseMessages.add(rm);

        BaseRepresentation baseRepresentation = new BaseRepresentation();
        baseRepresentation.setMessages(responseMessages);

        return new ResponseEntity<>(baseRepresentation, HttpStatus.BAD_REQUEST);
    }
    
    /**
     * This method handles KeyGenerationException.
     * KeyGenerationException is thrown when there is an issue with generating a key.
     * This could happen when the application tries to generate a key for encryption or decryption and encounters an
     * error.
     * The method creates a BaseRepresentation of the error with an "Invalid Key" message.
     * The method then returns a ResponseEntity with the BaseRepresentation and a HTTP status code of 400 (Bad Request).
     *
     * @param e the KeyGenerationException to handle
     * @return a ResponseEntity containing a BaseRepresentation of the "Invalid Key" error
     */
    @ExceptionHandler(KeyGenerationException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(KeyGenerationException e) {
        LOGGER.error(e.getMessage(), e);
        ResponseMessage errorResponse = new ResponseMessage(ResponseMessages.INVALID_KEY, e.getMessage());
        BaseRepresentation baseRepresentation = new BaseRepresentation();
        baseRepresentation.addMessage(errorResponse);
        return new ResponseEntity<>(baseRepresentation, HttpStatus.BAD_REQUEST);
    }

    /**
     * Handles RecordAlreadyExistsException, if record already exists in system.
     *
     * @param e - takes RecordAlreadyExistsException as input
     * @return response with https status code 409 conflict
     */
    @ExceptionHandler(RecordAlreadyExistsException.class)
    public ResponseEntity<BaseRepresentation> exceptionHandler(RecordAlreadyExistsException e) {
        LOGGER.error(RECORD_ALREADY_EXISTS_ERROR_MESSAGE, e);
        ResponseMessage errorResponse = new ResponseMessage("field.is.unique", e.getMessage());
        BaseRepresentation baseRepresentation = new BaseRepresentation();
        baseRepresentation.addMessage(errorResponse);
        return new ResponseEntity<>(baseRepresentation, HttpStatus.CONFLICT);
    }

    /**
     * Handles PatternMismatchException.
     * This exception occurs when there is a mismatch in the expected pattern.
     * The method creates a ModelAndView object for the "Forgot Password" recovery page.
     * It adds error messages and CAPTCHA details to the ModelAndView object.
     *
     * @return a ModelAndView object containing the error details and CAPTCHA information
     */
    @ExceptionHandler(PatternMismatchException.class)
    public ModelAndView patternMismatchException() {
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
        return new ModelAndView(RECOVERY_FORGOT_PASSWORD)
                .addObject(ERROR_LITERAL, ACC_NAME_FORMAT_ERROR)
                .addObject(CAPTCHA_FIELD_ENABLED, TRUE)
                .addObject(CAPTCHA_SITE, tenantProperties.getCaptcha().getRecaptchaKeySite());
    }

    /**
     * This method handles general exceptions and returns a "Bad Request" response.
     * It creates a BaseRepresentation of the error with a "Bad Request" message.
     * The method then returns a ResponseEntity with the BaseRepresentation and a HTTP status code of 400 (Bad Request).
     *
     * @param e the general Exception to handle
     * @return a ResponseEntity containing a BaseRepresentation of the "Bad Request" error
     */
    private ResponseEntity<BaseRepresentation> getBadRequestResponse(Exception e) {
        LOGGER.error(e.getMessage(), e);
        ResponseMessage errorResponse = new ResponseMessage(ResponseMessages.BAD_REQUEST);
        BaseRepresentation baseRepresentation = new BaseRepresentation();
        baseRepresentation.addMessage(errorResponse);
        return new ResponseEntity<>(baseRepresentation, HttpStatus.BAD_REQUEST);
    }

    /**
     * This method handles general exceptions and returns a "Resource Not Found" response.
     * It creates a BaseRepresentation of the error with a "Resource Not Found" message.
     * The method then returns a ResponseEntity with the BaseRepresentation and a HTTP status code of 400 (Bad Request).
     *
     * @param e the general Exception to handle
     * @return a ResponseEntity containing a BaseRepresentation of the "Resource Not Found" error
     */
    private ResponseEntity<BaseRepresentation> getResourceNotFoundResponse(Exception e) {
        LOGGER.error("Resource not found: ", e);
        ResponseMessage errorResponse = new ResponseMessage(ResponseMessages.RESOURCE_NOT_FOUND);
        BaseRepresentation baseRepresentation = new BaseRepresentation();
        baseRepresentation.addMessage(errorResponse);
        return new ResponseEntity<>(baseRepresentation, HttpStatus.BAD_REQUEST);
    }

    /**
     * This method handles CustomOauth2AuthorizationException.
     * This custom exception is thrown when there is an issue with OAuth2 Authorization.
     * The method returns a ResponseEntity containing a BaseResponse of the error.
     * The BaseResponse includes the error id, message, and HTTP status code.
     *
     * @param ex the CustomOauth2AuthorizationException to handle
     * @return a ResponseEntity containing a BaseResponse of the error
     */
    @ExceptionHandler(CustomOauth2AuthorizationException.class)
    private ResponseEntity<BaseResponse> customExceptionHandler(CustomOauth2AuthorizationException ex) {
        LOGGER.error("customOAuth2AuthorizationException encountered", ex);

        BaseResponse response = new BaseResponse(ex.getId(), ex.getMessage(), null,
            HttpStatus.valueOf(ex.getStatusCode()));

        return new ResponseEntity<>(response, response.getHttpStatus());

    }
}
