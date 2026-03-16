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

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Generic API response wrapper following the LLD specification.
 *
 * @param <T> the type of data in the response
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {
    
    private String status;
    private T data;
    private ErrorDetails error;
    
    /**
     * Creates a success response.
     *
     * @param data the response data
     * @param <T> the type of data
     * @return the API response
     */
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>("success", data, null);
    }
    
    /**
     * Creates a partial success response.
     *
     * @param data the response data
     * @param <T> the type of data
     * @return the API response
     */
    public static <T> ApiResponse<T> partialSuccess(T data) {
        return new ApiResponse<>("partial_success", data, null);
    }
    
    /**
     * Creates an error response.
     *
     * @param code the error code
     * @param message the error message
     * @param <T> the type of data
     * @return the API response
     */
    public static <T> ApiResponse<T> error(String code, String message) {
        return new ApiResponse<>("error", null, new ErrorDetails(code, message));
    }
    
    /**
     * Error details nested class.
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ErrorDetails {
        private String code;
        private String message;
    }
}
