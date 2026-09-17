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

package org.eclipse.ecsp.oauth2.server.core.utils;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for {@link OidcTokenHashingUtil}.
 */
class OidcTokenHashingUtilTest {

    @Test
    void createTokenHashUsesLeftHalfOfRs256Digest() {
        assertEquals("Pxa-1wifRlPl7yG_0oJNfw",
                OidcTokenHashingUtil.createTokenHash("access-token", SignatureAlgorithm.RS256));
        assertEquals("VpTQii5T_8rgwxA-Wtb2Bw",
                OidcTokenHashingUtil.createTokenHash("code", SignatureAlgorithm.RS256));
    }

    @Test
    void createTokenHashRejectsMissingArguments() {
        assertThrows(IllegalArgumentException.class,
                () -> OidcTokenHashingUtil.createTokenHash("", SignatureAlgorithm.RS256));
        assertThrows(IllegalArgumentException.class,
                () -> OidcTokenHashingUtil.createTokenHash("access-token", null));
    }
}
