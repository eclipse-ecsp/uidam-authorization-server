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

import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;
import javax.annotation.PostConstruct;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The TenantProperties class represents the properties related to a tenant.
 * Note: This class does not need @ConfigurationProperties as it's used as a nested property
 * within MultiTenantProperties which handles the binding.
 */
@Getter
@Setter
public class TenantProperties {
    private String tenantId;
    private String tenantName;
    private Boolean jksEnabled;
    @Pattern(regexp = "[A-Za-z]+")
    private String alias;
    private HashMap<String, String> contactDetails;
    private AccountProperties account;
    private UserProperties user;
    private ClientProperties client;
    private HashMap<String, String> externalIdpDetails;
    private HashMap<String, String> externalUrls;
    private HashMap<String, String> keyStore;
    private HashMap<String, String> cert;
    private CaptchaProperties captcha;
    
    
    // Legacy External IDP List (for backward compatibility and direct property binding)
    private List<ExternalIdpRegisteredClient> externalIdpRegisteredClientList;
    
    // Direct External IDP configuration fields for property binding
    private boolean externalIdpEnabled;
    private String externalIdpClientName;
    
    private boolean internalLoginEnabled = true;
    private boolean signUpEnabled;

    private static final String MAPPINGS_DELIMITER = ",";
    private static final String PAIR_DELIMITER = "#";
    private static final int EXPECTED_PAIR_LENGTH = 2;

    /**
     * Parses the claim mappings for external IDP registered clients. This method
     * processes the list of external IDP registered clients and extracts the claim
     * mappings from each client. If the claim mappings are not empty, they are
     * split into key-value pairs and stored in the respective client object. This
     * method is annotated with @PostConstruct, meaning it will be called after the
     * properties have been set and the bean is fully initialized.
     */
    @PostConstruct
    public void parseMappings() {
        if (externalIdpRegisteredClientList != null) {
            externalIdpRegisteredClientList.forEach(idpClient -> Optional.ofNullable(idpClient.getClaimMappings())
                    .filter(mappings -> !mappings.trim().isEmpty())
                    .map(mappings -> Arrays.stream(mappings.split(MAPPINGS_DELIMITER))
                            .map(pair -> pair.split(PAIR_DELIMITER)).filter(arr -> arr.length == EXPECTED_PAIR_LENGTH)
                            .collect(Collectors.toMap(arr -> arr[0].trim(), arr -> arr[1].trim())))
                    .ifPresent(idpClient::setMappings));
        }
    }

}
