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

import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Configuration for claims added to an OpenID Connect ID token.
 *
 * <p>The standard ID-token claims are managed by Spring Authorization Server and cannot be
 * supplied as additional claims. UIDAM user attributes can be selected with a comma-separated
 * tenant property, for example {@code id-token.additional-claims=email,firstName,profile}.
 */
public class IdTokenProperties {

    private static final Set<String> MANDATORY_CLAIMS = Set.of(
            JwtClaimNames.JTI,
            IdTokenClaimNames.ISS,
            IdTokenClaimNames.SUB,
            IdTokenClaimNames.AUD,
            IdTokenClaimNames.EXP,
            IdTokenClaimNames.IAT,
            IdTokenClaimNames.AUTH_TIME,
            IdTokenClaimNames.NONCE,
            IdTokenClaimNames.ACR,
            IdTokenClaimNames.AMR,
            IdTokenClaimNames.AZP,
            IdTokenClaimNames.AT_HASH,
            IdTokenClaimNames.C_HASH);

    /** Comma-separated UIDAM user attribute names to include in ID tokens. */
    private String additionalClaims = "";

    public String getAdditionalClaims() {
        return additionalClaims;
    }

    public void setAdditionalClaims(String additionalClaims) {
        this.additionalClaims = additionalClaims;
    }

    /**
     * Returns configured claim names after trimming whitespace and removing duplicates.
     *
     * @return configured additional ID-token claim names
     */
    public List<String> getAdditionalClaimNames() {
        if (!StringUtils.hasText(additionalClaims)) {
            return Collections.emptyList();
        }
        return Arrays.stream(additionalClaims.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    /**
     * Checks whether a claim is reserved for Spring Authorization Server.
     *
     * @param claimName claim name to inspect
     * @return {@code true} when the claim is a standard ID-token claim
     */
    public boolean isMandatoryClaim(String claimName) {
        return StringUtils.hasText(claimName)
                && MANDATORY_CLAIMS.contains(claimName.toLowerCase(Locale.ROOT));
    }
}
