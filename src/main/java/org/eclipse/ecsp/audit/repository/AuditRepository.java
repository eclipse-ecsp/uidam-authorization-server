/*
 * Copyright (c) 2024 - 2025 Harman International
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.eclipse.ecsp.audit.repository;

import org.eclipse.ecsp.audit.entity.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.math.BigInteger;

/**
 * Audit Repository for AuditEvent entity.
 * 
 * <p>Provides data access for audit log persistence.</p>
 * 
 * <p><strong>Important:</strong></p>
 * <ul>
 *   <li>Audit log is <strong>immutable</strong> - only save() method is exposed</li>
 *   <li>NO UPDATE or DELETE operations allowed</li>
 * </ul>
 *
 */
@Repository
public interface AuditRepository extends JpaRepository<AuditEvent, BigInteger> {
    // Only save() method from JpaRepository is used
    // Audit log is immutable - only INSERT operations allowed
}
