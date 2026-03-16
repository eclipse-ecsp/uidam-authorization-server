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

package org.eclipse.ecsp.oauth2.server.core.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Jackson mixin for CustomWebAuthenticationDetails serialization/deserialization.
 * This enables proper JSON serialization of custom authentication details including
 * browser metadata (user-agent, language, referer) along with standard fields.
 *
 * @author UIDAM Team
 * @since 1.0
 */
public abstract class CustomWebAuthenticationDetailsMixin {

    /**
     * Constructor for JSON deserialization.
     *
     * @param remoteAddress the remote IP address
     * @param sessionId the HTTP session ID
     * @param userAgent the User-Agent header value
     * @param acceptLanguage the Accept-Language header value
     * @param referer the Referer header value
     */
    @JsonCreator
    CustomWebAuthenticationDetailsMixin(
            @JsonProperty("remoteAddress") String remoteAddress,
            @JsonProperty("sessionId") String sessionId,
            @JsonProperty("userAgent") String userAgent,
            @JsonProperty("acceptLanguage") String acceptLanguage,
            @JsonProperty("referer") String referer) {
    }

    /**
     * Getter for userAgent property.
     *
     * @return the user agent string
     */
    @JsonProperty("userAgent")
    abstract String getUserAgent();

    /**
     * Getter for acceptLanguage property.
     *
     * @return the accept language string
     */
    @JsonProperty("acceptLanguage")
    abstract String getAcceptLanguage();

    /**
     * Getter for referer property.
     *
     * @return the referer URL
     */
    @JsonProperty("referer")
    abstract String getReferer();
}
