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

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Objects;

/**
 * Extended authentication details that includes browser user-agent information
 * and additional HTTP headers in addition to the standard remote address and session ID.
 *
 * <p>This class captures the following additional information:
 * <ul>
 *   <li>User-Agent: Browser/client identification string</li>
 *   <li>Accept-Language: Client's preferred language</li>
 *   <li>Referer: The referring page URL</li>
 * </ul>
 *
 * @author UIDAM Team
 * @since 1.0
 */
public class CustomWebAuthenticationDetails extends WebAuthenticationDetails {

    private static final long serialVersionUID = 1L;

    private final String userAgent;
    private final String acceptLanguage;
    private final String referer;

    /**
     * Constructor that extracts additional browser details from the HTTP request.
     *
     * @param request the HTTP request containing authentication details
     */
    public CustomWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.userAgent = request.getHeader("User-Agent");
        this.acceptLanguage = request.getHeader("Accept-Language");
        this.referer = request.getHeader("Referer");
    }

    /**
     * Constructor for Jackson serialization/deserialization support.
     *
     * @param remoteAddress the remote IP address
     * @param sessionId the HTTP session ID
     * @param userAgent the User-Agent header value
     * @param acceptLanguage the Accept-Language header value
     * @param referer the Referer header value
     */
    public CustomWebAuthenticationDetails(String remoteAddress, String sessionId, 
                                         String userAgent, String acceptLanguage, 
                                         String referer) {
        super(remoteAddress, sessionId);
        this.userAgent = userAgent;
        this.acceptLanguage = acceptLanguage;
        this.referer = referer;
    }

    /**
     * Returns the User-Agent header from the authentication request.
     * This typically contains browser name, version, and operating system information.
     *
     * @return the user agent string, or null if not present in the request
     */
    public String getUserAgent() {
        return this.userAgent;
    }

    /**
     * Returns the Accept-Language header from the authentication request.
     * This indicates the client's preferred language(s).
     *
     * @return the accept language string, or null if not present in the request
     */
    public String getAcceptLanguage() {
        return this.acceptLanguage;
    }

    /**
     * Returns the Referer header from the authentication request.
     * This indicates the URL of the page that linked to the authentication request.
     *
     * @return the referer URL, or null if not present in the request
     */
    public String getReferer() {
        return this.referer;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        CustomWebAuthenticationDetails that = (CustomWebAuthenticationDetails) o;
        return Objects.equals(userAgent, that.userAgent)
               && Objects.equals(acceptLanguage, that.acceptLanguage)
               && Objects.equals(referer, that.referer);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), userAgent, acceptLanguage, referer);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName()).append(" [");
        sb.append("RemoteIpAddress=").append(getRemoteAddress()).append(", ");
        sb.append("SessionId=").append(getSessionId()).append(", ");
        sb.append("UserAgent=").append(maskSensitiveData(this.userAgent)).append(", ");
        sb.append("AcceptLanguage=").append(this.acceptLanguage).append(", ");
        sb.append("Referer=").append(maskSensitiveData(this.referer));
        sb.append("]");
        return sb.toString();
    }

    /**
     * Masks sensitive data for logging purposes.
     * If the data is longer than 50 characters, it will be truncated and "..." appended.
     *
     * @param data the data to mask
     * @return the masked data, or the original if null or short enough
     */
    private String maskSensitiveData(String data) {
        final int maxLength = 50;
        if (data == null || data.length() <= maxLength) {
            return data;
        }
        return data.substring(0, maxLength) + "...";
    }
}
