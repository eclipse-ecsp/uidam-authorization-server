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

package org.eclipse.ecsp.oauth2.server.core.common.constants;

/**
 * The ResponseMessages class is a utility class that holds constant values representing various response messages.
 */
public class ResponseMessages {

    private ResponseMessages() {}

    public static final String PARSING_FAILURE = "parsing.failure";
    public static final String MISSING_MANDATORY_PARAMETERS = "missing.mandatory.parameters";
    public static final String MISSING_REQUEST_HEADER = "missing.request.header";
    public static final String BAD_REQUEST = "bad.request";
    public static final String INTERNAL_ERROR = "internal.error";
    public static final String RESOURCE_NOT_FOUND = "resource.not.found";
    public static final String BAD_GATEWAY = "bad.gateway";
    public static final String INVALID_KEY = "Errors while generating RSA key";
    public static final String MISSING_CORRELATION_ID = "missing.correlation.id";


    public static final String USER_LOCKED_ERROR =
        "Consecutive log-in failures exceeded the maximum allowed login attempt. "
            + "Your account has been locked, Please contact admin!";

    /**
     * Generic authentication failure message that does not reveal whether the username exists.
     * This prevents username enumeration attacks.
     */
    public static final String INVALID_CREDENTIALS_ERROR = "Invalid username or password";
}
