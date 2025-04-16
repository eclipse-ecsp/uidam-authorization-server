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

package org.eclipse.ecsp.oauth2.server.core.service;


import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.ecsp.oauth2.server.core.exception.ReCaptchaInvalidException;

/**
 * The CaptchaService interface provides the contract for a service that handles CAPTCHA functionality.
 */
public interface CaptchaService {


    default void processResponse(final String response, HttpServletRequest request) throws ReCaptchaInvalidException {}

    String getReCaptchaSite();

    String getReCaptchaSecret();
}