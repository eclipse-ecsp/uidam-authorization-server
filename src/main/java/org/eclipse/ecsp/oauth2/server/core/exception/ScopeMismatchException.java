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

package org.eclipse.ecsp.oauth2.server.core.exception;

/**
 * Thrown by {@link org.eclipse.ecsp.oauth2.server.core.service.ScopeRoleClaimMappingService}
 * when a dynamic external-role to internal-scope mapping was applied for the current federated
 * login, but the user's internal UIDAM scopes (from user-management) have zero overlap with the
 * scopes resolved from the external IDP's claim mapping rules.
 *
 * <p>This indicates an inconsistency between what the user is internally provisioned for and what
 * the external IDP is currently asserting, and the login is failed rather than silently proceeding
 * with a possibly incorrect scope set.
 */
public class ScopeMismatchException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new {@link ScopeMismatchException} with the given detail message.
     *
     * @param message the detail message describing the scope mismatch
     */
    public ScopeMismatchException(String message) {
        super(message);
    }
}
