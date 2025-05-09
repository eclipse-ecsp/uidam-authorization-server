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

/**
 * The InvalidSecretException class extends the RuntimeException class.
 * This class represents a custom exception that is thrown when an invalid secret is encountered.
 */
public class InvalidSecretException extends RuntimeException {
    /**
     * serial version uid.
     */
    private static final long serialVersionUID = -2784193528313541545L;

    /**
     * This is a parameterized constructor for the InvalidSecretException class.
     * It initializes the superclass with the provided message.
     *
     * @param message a string representing the detailed exception message
     */
    public InvalidSecretException(String message) {
        super(message);
    }
}
