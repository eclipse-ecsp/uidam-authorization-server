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

package org.eclipse.ecsp.oauth2.server.core.cache.impl;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.ecsp.oauth2.server.core.cache.CacheClientService;
import org.eclipse.ecsp.oauth2.server.core.cache.ClientCacheDetails;
import org.eclipse.ecsp.oauth2.server.core.client.AuthManagementClient;
import org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails;
import org.eclipse.ecsp.oauth2.server.core.service.RegisteredClientMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;


import java.util.Arrays;
import java.util.List;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLIENT_CACHE_KEY;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLIENT_CACHE_UNLESS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.CLIENT_CACHE_VALUE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.COMMA_DELIMITER;

/**
 * Service implementation for caching client details using Caffeine.
 */
@Service
public class CacheClientServiceImpl implements CacheClientService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CacheClientServiceImpl.class);

    @Autowired
    AuthManagementClient authManagementClient;
    
    @Autowired
    RegisteredClientMapper registeredClientMapper;

    @Value("${cache.client.ids}")
    private String cacheClientIds;
    
    private List<String> cacheClientIdList = null;

    /**
     * Retrieves client details with synchronization enabled.
     * This method is cached using the specified cache value and key.
     *
     * @param clientId the ID of the client to retrieve details for
     * @param tenantId the ID of the tenant
     * @return the client cache details
     */
    @Cacheable(value = CLIENT_CACHE_VALUE, key = CLIENT_CACHE_KEY, sync = true)
    @Override
    public ClientCacheDetails getClientDetailsWithSync(String clientId, String tenantId) {
        ClientCacheDetails clientCacheDetails = getClientDetailsFromAuthMgmt(clientId);
        if (clientCacheDetails == null) {
            return null;
        }
        LOGGER.info("Putting client details in cache for client id: {}", clientId);
        return clientCacheDetails;
    }

    /**
     * Retrieves client details with synchronization disabled.
     * This method is cached using the specified cache value and key, unless the condition is met.
     *
     * @param clientId the ID of the client to retrieve details for
     * @param tenantId the ID of the tenant
     * @return the client cache details
     */
    @Cacheable(value = CLIENT_CACHE_VALUE, key = CLIENT_CACHE_KEY, unless = CLIENT_CACHE_UNLESS)
    @Override
    public ClientCacheDetails getClientDetailsWithoutSync(String clientId, String tenantId) {
        ClientCacheDetails clientCacheDetails = getClientDetailsFromAuthMgmt(clientId);
        if (clientCacheDetails == null) {
            return null;
        }
        boolean cache = isCacheRequired(clientId, clientCacheDetails.getRegisteredClient());
        clientCacheDetails.setCache(cache);
        if (cache) {
            LOGGER.info("Putting client details in cache for client id: {} and tenant: {}", clientId, tenantId);
        }
        return clientCacheDetails;
    }

    /**
     * Fetches client details from the AuthManagementClient.
     *
     * @param clientId the ID of the client to retrieve details for
     * @return the client cache details
     */
    private ClientCacheDetails getClientDetailsFromAuthMgmt(String clientId) {
        RegisteredClientDetails registeredClientDetails =  authManagementClient.getClientDetails(clientId);
        if (registeredClientDetails == null) {
            return null;
        }
        RegisteredClient registeredClient = registeredClientMapper.toRegisteredClient(registeredClientDetails);
        ClientCacheDetails clientCacheDetails = new ClientCacheDetails();
        clientCacheDetails.setRegisteredClient(registeredClient);
        clientCacheDetails.setTenantId(registeredClientDetails.getTenantId());
        clientCacheDetails.setClientType(registeredClientDetails.getClientType());
        clientCacheDetails.setAccountType(registeredClientDetails.getAccountType());
        clientCacheDetails.setAccountName(registeredClientDetails.getAccountName());
        clientCacheDetails.setAccountId(registeredClientDetails.getAccountId());
        return clientCacheDetails;
    }

    /**
     * Determines if caching is required for a given client.
     *
     * @param clientId the ID of the client to check
     * @param registeredClient the RegisteredClient instance containing client details
     * @return true if caching is required, false otherwise
     */
    private boolean isCacheRequired(String clientId, RegisteredClient registeredClient) {
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            return true;
        }
        if (StringUtils.isNotEmpty(cacheClientIds)) {
            if (cacheClientIdList == null) {
                cacheClientIdList = Arrays.asList(cacheClientIds.split(COMMA_DELIMITER));
            }
            return cacheClientIdList.contains(clientId);
            
        }
        return false;
    }

}