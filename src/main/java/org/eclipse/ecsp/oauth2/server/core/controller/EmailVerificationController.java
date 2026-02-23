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

package org.eclipse.ecsp.oauth2.server.core.controller;

import org.eclipse.ecsp.oauth2.server.core.utils.TenantUtils;
import org.eclipse.ecsp.oauth2.server.core.utils.UiAttributeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.util.Locale;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.SUCCESS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ERROR_LITERAL;

/**
 * The EmailVerificationController class is a REST controller that manages the email verification process.
 * It exposes the /emailVerification/verify endpoint for this purpose.
 */
@Controller
@RequestMapping({"/{tenantId}/emailVerification", "/emailVerification"})
public class EmailVerificationController {

    private static final Logger LOGGER = LoggerFactory.getLogger(EmailVerificationController.class);
    private final UiAttributeUtils uiAttributeUtils;

    private static final String TRUE = "true";
    private static final String FALSE = "false";

    /**
     * Constructor for EmailVerificationController.
     *
     * @param uiAttributeUtils the utility for adding UI attributes to models
     */
    public EmailVerificationController(UiAttributeUtils uiAttributeUtils) {
        this.uiAttributeUtils = uiAttributeUtils;
    }

    /**
     * This method handles the GET request for the email verification operation.
     * It checks the verification status and updates it if necessary, adds the verification status to the model,
     * and returns a ModelAndView object.
     * The verification status can be "error", "true", or "false".
     * "error" - if the token is invalid/expired or email data does not exist.
     * "true" - if email verification is successful for the input token.
     * "false" - if email validation failed due to some system error.
     *
     * @param verifyStatus The verification status.
     * @param model The Model object to bind to the view.
     * @return A ModelAndView object that includes the view name and model attributes.
     */
    @GetMapping("/verify")
    public ModelAndView verifyEmail(@PathVariable(value = "tenantId", required = false) String tenantId,
                                    @RequestParam(SUCCESS) String verifyStatus, Model model) {
        tenantId = TenantUtils.resolveTenantId(tenantId);
        if (!ERROR_LITERAL.equalsIgnoreCase(verifyStatus) && !TRUE.equalsIgnoreCase(verifyStatus)
            && !FALSE.equalsIgnoreCase(verifyStatus)) {
            LOGGER.info("Reassigning verification status to error as invalid verification status provided");
            verifyStatus = ERROR_LITERAL;
        }
        verifyStatus = verifyStatus.toLowerCase(Locale.ROOT);
        LOGGER.info("Email Verification is verified: {}", verifyStatus);
        model.addAttribute(SUCCESS, verifyStatus);
        
        // Add UI configuration attributes based on tenant properties
        uiAttributeUtils.addUiAttributes(model, tenantId);
        
        return new ModelAndView("emailVerify/email-verification").addObject(model);
    }
}
