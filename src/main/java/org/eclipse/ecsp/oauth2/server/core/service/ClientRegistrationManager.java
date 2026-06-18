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

import lombok.AllArgsConstructor;
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * The ClientRegistrationManager class is an implementation of the RegisteredClientRepository interface.
 */
@Service
@AllArgsConstructor
public class ClientRegistrationManager implements RegisteredClientRepository {
    private static final Logger LOGGER = LoggerFactory.getLogger(ClientRegistrationManager.class);

    @Autowired
    CacheClientUtils cacheClientUtils;

    /**
     * This method is used to save a RegisteredClient instance.
     * The actual saving is handled by the Auth Management component.
     *
     * @param registeredClient the RegisteredClient instance to be saved.
     */
    @Override
    public void save(RegisteredClient registeredClient) {
        // Saving client would be handled by Auth Management component
    }

    /**
     * This method is used to update a RegisteredClient instance.
     * The actual updating is handled by the Auth Management component.
     *
     * @param registeredClient the RegisteredClient instance to be updated.
     */
    public void update(RegisteredClient registeredClient) {
        // Update client would be handled by Auth Management component
    }

    /**
     * This method is used to find a RegisteredClient instance by its id.
     * It fetches the client details from the Auth Management component and converts them into a RegisteredClient
     * instance.
     *
     * @param id the id of the RegisteredClient instance to be found.
     * @return the found RegisteredClient instance, or null if not found.
     */
    @Override
    public RegisteredClient findById(String id) {
        LOGGER.info("## findById - START");
        ClientCacheDetails clientDetails = cacheClientUtils.getClientDetails(id);
        if (Optional.ofNullable(clientDetails).isPresent()) {
            LOGGER.info("## findById - END");
            return clientDetails.getRegisteredClient();
        } else {
            LOGGER.info("## issue while fetching client details for clientId {} - END", id);
            return null;
        }
    }

    /**
     * This method is used to find a RegisteredClient instance by its client id.
     * It fetches the client details from the Auth Management component and converts them into a RegisteredClient
     * instance.
     *
     * @param clientId the client id of the RegisteredClient instance to be found.
     * @return the found RegisteredClient instance, or null if not found.
     */
    @Override
    public RegisteredClient findByClientId(String clientId) {
        LOGGER.debug("## findByClientId {} - START :: ", clientId);
        ClientCacheDetails clientDetails = cacheClientUtils.getClientDetails(clientId);
        if (Optional.ofNullable(clientDetails).isPresent()) {
            LOGGER.debug("## findByClientId {} - END", clientId);
            return clientDetails.getRegisteredClient();
        } else {
            LOGGER.info("## issue while fetching client details for clientId {} - END", clientId);
            return null;
        }
    }

}