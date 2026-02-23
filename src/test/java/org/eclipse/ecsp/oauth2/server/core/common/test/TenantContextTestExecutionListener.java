/********************************************************************************
 * Copyright (c) 2023 - 2024 Harman International
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

package org.eclipse.ecsp.oauth2.server.core.common.test;

import org.eclipse.ecsp.sql.multitenancy.TenantContext;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestExecutionListener;

/**
 * Test execution listener that sets up tenant context before Spring context loads.
 * This ensures that tenant context is available during bean initialization.
 */
public class TenantContextTestExecutionListener implements TestExecutionListener {

    @Override
    public void beforeTestClass(TestContext testContext) {
        TenantContext.setCurrentTenant("ecsp");
    }

    @Override
    public void beforeTestMethod(TestContext testContext) {
        TenantContext.setCurrentTenant("ecsp");
    }

    @Override
    public void afterTestMethod(TestContext testContext) {
        TenantContext.clear();
    }

    @Override
    public void afterTestClass(TestContext testContext) {
        TenantContext.clear();
    }
}
