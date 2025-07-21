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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * This class tests the functionality of the EmailVerificationController.
 */
@WebMvcTest(EmailVerificationController.class)
@ContextConfiguration(classes = {EmailVerificationController.class})
class EmailVerificationControllerTest {

    @Autowired
    private WebApplicationContext applicationContext;

    private MockMvc mockMvc;

    /**
     * This method sets up the test environment before each test.
     * It initializes the MockMvc instance.
     */
    @BeforeEach
    void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.applicationContext).build();
    }

    /**
     * This method tests the scenario where the email verification is successful.
     * It performs a GET request to the /emailVerification/verify endpoint with a success parameter set to true.
     * The test asserts that the returned status is HttpStatus.OK, the view name is /emailVerify/email-verification, and
     * the success model attribute is true.
     */
    @Test
    void testVerifyEmailSuccess() throws Exception {
        this.mockMvc
            .perform(get("/emailVerification/verify")
                         .param("success", "true"))
            .andExpect(status().isOk())
            .andExpect(view().name("/emailVerify/email-verification"))
            .andExpect(model().attributeExists("success"))
            .andExpect(model().attribute("success", "true"));
    }

    /**
     * This method tests the scenario where the email verification fails.
     * It performs a GET request to the /emailVerification/verify endpoint with a success parameter set to false.
     * The test asserts that the returned status is HttpStatus.OK, the view name is /emailVerify/email-verification, and
     * the success model attribute is false.
     */
    @Test
    void testVerifyEmailFailure() throws Exception {
        this.mockMvc
            .perform(get("/emailVerification/verify")
                         .param("success", "false"))
            .andExpect(status().isOk())
            .andExpect(view().name("/emailVerify/email-verification"))
            .andExpect(model().attributeExists("success"))
            .andExpect(model().attribute("success", "false"));
    }

    /**
     * This method tests the scenario where the email verification encounters an error.
     * It performs a GET request to the /emailVerification/verify endpoint with a success parameter set to error.
     * The test asserts that the returned status is HttpStatus.OK, the view name is /emailVerify/email-verification, and
     * the success model attribute is error.
     */
    @Test
    void testVerifyEmailError() throws Exception {
        this.mockMvc
            .perform(get("/emailVerification/verify")
                         .param("success", "error"))
            .andExpect(status().isOk())
            .andExpect(view().name("/emailVerify/email-verification"))
            .andExpect(model().attributeExists("success"))
            .andExpect(model().attribute("success", "error"));
    }

    /**
     * This method tests the scenario where the email verification status is incorrect.
     * It performs a GET request to the /emailVerification/verify endpoint with a success parameter set to a random
     * value.
     * The test asserts that the returned status is HttpStatus.OK, the view name is /emailVerify/email-verification, and
     * the success model attribute is error.
     */
    @Test
    void testVerifyEmailIncorrectStatus() throws Exception {
        this.mockMvc
            .perform(get("/emailVerification/verify")
                         .param("success", "random_value"))
            .andExpect(status().isOk())
            .andExpect(view().name("/emailVerify/email-verification"))
            .andExpect(model().attributeExists("success"))
            .andExpect(model().attribute("success", "error"));
    }
}