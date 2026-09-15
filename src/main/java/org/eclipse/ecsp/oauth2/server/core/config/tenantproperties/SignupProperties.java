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

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import lombok.Getter;
import lombok.Setter;

/**
 * Signup-level feature flags.
 * Bound from {@code tenant.props.*.signup.*}.
 */
@Getter
@Setter
public class SignupProperties {

    /**
     * Master switch for the dynamic additional-attributes section on the sign-up form.
     * When {@code false}, no attributes from {@code user_attributes} are fetched or rendered;
     * only the fixed mandatory fields are shown.
     * Default: {@code false} (feature disabled).
     */
    private boolean additionalAttributesEnabled = false;
}
