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

package org.eclipse.ecsp.oauth2.server.core.config.tenantproperties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.util.StringUtils;

/**
 * The UiProperties class represents the Ui-related properties for a tenant.
 * This includes logo path and stylesheet path for tenant-specific branding.
 */
@Getter
@Setter
public class UiProperties {

    private String logoPath;
    private String stylesheetPath;
    private String termsPrivacyPolicy;

    /**
     * Gets the logo path for the tenant, with fallback to default logo
     * based on tenant ID if no specific logo path is configured.
     *
     * @param tenantId The tenant ID to use for fallback logo path
     * @return The logo path to use for this tenant
     */
    public String getLogoPath(String tenantId) {
        if (StringUtils.hasText(logoPath)) {
            return logoPath;
        }
        // Default fallback based on tenant ID
        return "/images/" + tenantId + "-logo.svg";
    }

    /**
     * Gets the stylesheet path for the tenant, with fallback to default stylesheet
     * if no specific stylesheet path is configured.
     *
     * @return The stylesheet path to use for this tenant
     */
    public String getStylesheetPath() {
        if (StringUtils.hasText(stylesheetPath)) {
            return stylesheetPath;
        }
        // Default fallback
        return "/css/style.css";
    }
}
