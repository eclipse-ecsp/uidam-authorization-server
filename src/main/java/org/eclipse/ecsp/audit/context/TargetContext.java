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

package org.eclipse.ecsp.audit.context;

import java.util.Map;

/**
 * Target Context - Contains information about the entity being acted upon.
 * Implementations should return JSON-serializable data.
 * PII fields will be automatically masked before database storage.
 *
 * @version 2.0.0
 * @since 1.2.0
 */
public interface TargetContext {
    
    /**
     * Get target context as a map for JSON serialization.
     * PII fields in this map will be automatically masked.
     *
     * @return map of target context data
     */
    Map<String, Object> toMap();
}
