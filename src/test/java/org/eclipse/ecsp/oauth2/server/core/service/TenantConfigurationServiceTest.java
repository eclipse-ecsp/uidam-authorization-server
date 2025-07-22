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

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.AccountProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ClientProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.MultiTenantProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.UserProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;


import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.ECSP;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_CONTACT_NAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EMAIL;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_IDP_CLIENT_ID;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_IDP_CLIENT_SECRET;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_CLIENT_BY_CLIENT_ID_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_EXTERNAL_URLS_USER_BY_USERNAME_ENDPOINT;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_ALIAS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_FILENAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_PASS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_PHONE_NUMBER;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.ENFORCE_AFTER_FAILURE_COUNT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

/**
 * This class tests the functionality of the TenantConfigurationService.
 */
@ExtendWith(MockitoExtension.class)
class TenantConfigurationServiceTest {
    
    @Mock
    private MultiTenantProperties multiTenantProperties;
    
    private TenantConfigurationService tenantConfigurationService;

    @BeforeEach
    void setUp() {
        tenantConfigurationService = new TenantConfigurationService(multiTenantProperties);
    }

    /**
     * This test method tests the getTenantProperties method of the TenantConfigurationService.
     * It asserts that the returned TenantProperties object has the expected values for its properties.
     */
    @Test
    void getTenantPropertiesTest() {
        // Setup the expected tenant properties
        TenantProperties expectedTenantProperties = createMockTenantProperties();
        
        // Setup the mock to return the tenant properties
        Map<String, TenantProperties> tenants = new HashMap<>();
        tenants.put(ECSP, expectedTenantProperties);
        when(multiTenantProperties.getTenants()).thenReturn(tenants);
        
        // Execute the method under test
        TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties(ECSP);
        
        // Verify the results
        assertEquals("uidam", tenantProperties.getTenantId());
        assertEquals("uidam", tenantProperties.getTenantName());
        assertEquals("ecsp", tenantProperties.getAlias());
        assertEquals(1, tenantProperties.getClient().getAccessTokenTtl());
        assertEquals(1, tenantProperties.getClient().getIdTokenTtl());
        assertEquals(1, tenantProperties.getClient().getRefreshTokenTtl());
        assertEquals(1, tenantProperties.getClient().getAuthCodeTtl());
        assertEquals(false, tenantProperties.getClient().getReuseRefreshToken());
        assertEquals("ChangeMe", tenantProperties.getClient().getSecretEncryptionKey());
        assertEquals("ChangeMe", tenantProperties.getClient().getSecretEncryptionSalt());
        assertEquals("admin", tenantProperties.getContactDetails().get(TENANT_CONTACT_NAME));
        assertEquals("8888888888", tenantProperties.getContactDetails().get(TENANT_PHONE_NUMBER));
        assertEquals("john.doe@domain.com", tenantProperties.getContactDetails().get(TENANT_EMAIL));
        assertEquals(ENFORCE_AFTER_FAILURE_COUNT, tenantProperties.getUser().getCaptchaAfterInvalidFailures());
        assertEquals(Boolean.FALSE, tenantProperties.getUser().getCaptchaRequired());
        assertEquals("ecsp", tenantProperties.getAccount().getAccountId());
        assertEquals("ecsp", tenantProperties.getAccount().getAccountName());
        assertEquals("ecsp", tenantProperties.getAccount().getAccountType());
        assertEquals("ignite", tenantProperties.getExternalIdpDetails().get(TENANT_EXTERNAL_IDP_CLIENT_ID));
        assertEquals("secret", tenantProperties.getExternalIdpDetails().get(TENANT_EXTERNAL_IDP_CLIENT_SECRET));
        assertEquals("/v1/users/{userName}/byUserName", tenantProperties.getExternalUrls()
                .get(TENANT_EXTERNAL_URLS_USER_BY_USERNAME_ENDPOINT));
        assertEquals("/v1/oauth2/client/{clientId}", tenantProperties.getExternalUrls().get(
                TENANT_EXTERNAL_URLS_CLIENT_BY_CLIENT_ID_ENDPOINT));
        assertEquals("uidamauthserver.jks", tenantProperties.getKeyStore().get(TENANT_KEYSTORE_FILENAME));
        assertEquals("uidam-test-pwd", tenantProperties.getKeyStore().get(TENANT_KEYSTORE_PASS));
        assertEquals("uidam-dev", tenantProperties.getKeyStore().get(TENANT_KEYSTORE_ALIAS));
    }
    
    private TenantProperties createMockTenantProperties() {
        TenantProperties tenantProperties = new TenantProperties();
        tenantProperties.setTenantId("uidam");
        tenantProperties.setTenantName("uidam");
        tenantProperties.setAlias("ecsp");
        
        // Client properties
        ClientProperties clientProperties = new ClientProperties();
        clientProperties.setAccessTokenTtl(1);
        clientProperties.setIdTokenTtl(1);
        clientProperties.setRefreshTokenTtl(1);
        clientProperties.setAuthCodeTtl(1);
        clientProperties.setReuseRefreshToken(false);
        clientProperties.setSecretEncryptionKey("ChangeMe");
        clientProperties.setSecretEncryptionSalt("ChangeMe");
        tenantProperties.setClient(clientProperties);
        
        // Contact details
        HashMap<String, String> contactDetails = new HashMap<>();
        contactDetails.put(TENANT_CONTACT_NAME, "admin");
        contactDetails.put(TENANT_PHONE_NUMBER, "8888888888");
        contactDetails.put(TENANT_EMAIL, "john.doe@domain.com");
        tenantProperties.setContactDetails(contactDetails);
        
        // User properties
        UserProperties userProperties = new UserProperties();
        userProperties.setCaptchaAfterInvalidFailures(ENFORCE_AFTER_FAILURE_COUNT);
        userProperties.setCaptchaRequired(Boolean.FALSE);
        tenantProperties.setUser(userProperties);
        
        // Account properties
        AccountProperties accountProperties = new AccountProperties();
        accountProperties.setAccountId("ecsp");
        accountProperties.setAccountName("ecsp");
        accountProperties.setAccountType("ecsp");
        tenantProperties.setAccount(accountProperties);
        
        // External IDP details
        HashMap<String, String> externalIdpDetails = new HashMap<>();
        externalIdpDetails.put(TENANT_EXTERNAL_IDP_CLIENT_ID, "ignite");
        externalIdpDetails.put(TENANT_EXTERNAL_IDP_CLIENT_SECRET, "secret");
        tenantProperties.setExternalIdpDetails(externalIdpDetails);
        
        // External URLs
        HashMap<String, String> externalUrls = new HashMap<>();
        externalUrls.put(TENANT_EXTERNAL_URLS_USER_BY_USERNAME_ENDPOINT, "/v1/users/{userName}/byUserName");
        externalUrls.put(TENANT_EXTERNAL_URLS_CLIENT_BY_CLIENT_ID_ENDPOINT, "/v1/oauth2/client/{clientId}");
        tenantProperties.setExternalUrls(externalUrls);
        
        // Key store
        HashMap<String, String> keyStore = new HashMap<>();
        keyStore.put(TENANT_KEYSTORE_FILENAME, "uidamauthserver.jks");
        keyStore.put(TENANT_KEYSTORE_PASS, "uidam-test-pwd");
        keyStore.put(TENANT_KEYSTORE_ALIAS, "uidam-dev");
        tenantProperties.setKeyStore(keyStore);
        
        return tenantProperties;
    }
}