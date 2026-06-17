/********************************************************************************
 *
 * <p>
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
 *******************************************************************************/

package org.eclipse.ecsp.oauth2.server.core.mfa;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for MfaProperties and MfaProperties.Recovery configuration beans.
 */
class MfaPropertiesTest {

    @Test
    void defaultValues_areCorrect() {
        MfaProperties props = new MfaProperties();

        assertTrue(props.isEnabled());
        assertEquals("UIDAM", props.getAppName());
        assertNotNull(props.getRecovery());
        assertEquals(60, props.getRecovery().getResendCooldownSeconds());
    }

    @Test
    void setEnabled_updatesValue() {
        MfaProperties props = new MfaProperties();
        props.setEnabled(false);

        assertEquals(false, props.isEnabled());
    }

    @Test
    void setAppName_updatesValue() {
        MfaProperties props = new MfaProperties();
        props.setAppName("MyApp");

        assertEquals("MyApp", props.getAppName());
    }

    @Test
    void setRecovery_updatesValue() {
        MfaProperties props = new MfaProperties();
        MfaProperties.Recovery recovery = new MfaProperties.Recovery();
        recovery.setResendCooldownSeconds(120);
        props.setRecovery(recovery);

        assertEquals(120, props.getRecovery().getResendCooldownSeconds());
    }

    @Test
    void recovery_setResendCooldownSeconds_updatesValue() {
        MfaProperties.Recovery recovery = new MfaProperties.Recovery();
        recovery.setResendCooldownSeconds(30);

        assertEquals(30, recovery.getResendCooldownSeconds());
    }

    @Test
    void recovery_defaultResendCooldownSeconds_is60() {
        MfaProperties.Recovery recovery = new MfaProperties.Recovery();

        assertEquals(60, recovery.getResendCooldownSeconds());
    }

    @Test
    void mfaProperties_canBeCreatedWithDefaultConstructor() {
        MfaProperties props = new MfaProperties();
        assertNotNull(props);
    }

    @Test
    void recovery_canBeCreatedWithDefaultConstructor() {
        MfaProperties.Recovery recovery = new MfaProperties.Recovery();
        assertNotNull(recovery);
    }
}
