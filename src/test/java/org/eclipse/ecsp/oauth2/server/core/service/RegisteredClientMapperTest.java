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

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ClientProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.request.dto.RegisteredClientDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.stream.Stream;

import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.getClient;
import static org.eclipse.ecsp.oauth2.server.core.test.TestCommonStaticData.getClientWithEmptyScope;
import static org.eclipse.ecsp.oauth2.server.core.test.TestConstants.SECONDS_300;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * This class tests the functionality of the RegisteredClientMapper.
 */
@ExtendWith(MockitoExtension.class) 
@MockitoSettings(strictness = Strictness.LENIENT) 
@ActiveProfiles("test")
class RegisteredClientMapperTest {

    private static final int ACCESS_TOKEN_TTL = 3600;
    private static final int REFRESH_TOKEN_TTL = 7200;

    @Mock
    TenantConfigurationService tenantConfigurationService;

    @InjectMocks
    RegisteredClientMapper registeredClientMapper;

    /**
     * This method sets up the test environment before each test. It initializes the mocks.
     */
    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(registeredClientMapper, "bcryptLength", "high");

        // Set up default tenant configuration mock
        ClientProperties clientProperties = Mockito.mock(ClientProperties.class);
        Mockito.when(clientProperties.getAccessTokenTtl()).thenReturn(ACCESS_TOKEN_TTL);
        Mockito.when(clientProperties.getIdTokenTtl()).thenReturn(ACCESS_TOKEN_TTL);
        Mockito.when(clientProperties.getRefreshTokenTtl()).thenReturn(REFRESH_TOKEN_TTL);
        Mockito.when(clientProperties.getAuthCodeTtl()).thenReturn(SECONDS_300);
        Mockito.when(clientProperties.getReuseRefreshToken()).thenReturn(true);

        TenantProperties tenantProperties = Mockito.mock(TenantProperties.class);
        Mockito.when(tenantProperties.getClient()).thenReturn(clientProperties);
        Mockito.when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
    }

    /**
     * Tests the conversion of a client to a RegisteredClient instance. It sets up a mock ClientProperties instance and
     * configures the tenantConfigurationService mock to return it. Then, it verifies that the registeredClientMapper
     * correctly converts the client to a RegisteredClient instance.
     */
    @Test
    void testToRegisteredClient() {
        RegisteredClient registeredClient = registeredClientMapper.toRegisteredClient(getClient());
        assert registeredClient != null;
        assertEquals("testClientId", registeredClient.getClientId());
    }

    /**
     * Tests the conversion of a client with specific properties to a RegisteredClient instance. It sets up a
     * ClientProperties instance with predefined TTL values and configures the tenantConfigurationService mock to return
     * it. Then, it verifies that the registeredClientMapper correctly converts the client to a RegisteredClient
     * instance.
     */
    @Test
    void testToRegisteredClient2() {
        ClientProperties clientProperties = new ClientProperties();
        clientProperties.setAccessTokenTtl(SECONDS_300);
        clientProperties.setAuthCodeTtl(SECONDS_300);
        clientProperties.setRefreshTokenTtl(SECONDS_300);
        clientProperties.setReuseRefreshToken(false);
        TenantProperties tenantProperties = Mockito.mock(TenantProperties.class);
        Mockito.when(tenantProperties.getClient()).thenReturn(clientProperties);
        Mockito.when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);

        RegisteredClientDetails registeredClientDetails = getClientWithEmptyScope();
        registeredClientDetails.setRedirectUris(null);
        registeredClientDetails.setClientAuthenticationMethods(null);
        registeredClientDetails.setAccessTokenValidity(0);
        registeredClientDetails.setAuthorizationCodeValidity(0);
        registeredClientDetails.setRefreshTokenValidity(0);
        RegisteredClient registeredClient = registeredClientMapper.toRegisteredClient(registeredClientDetails);
        assert registeredClient != null;
        assertEquals("testClientId", registeredClient.getClientId());
    }

    /**
     * Provides a stream of arguments for parameterized tests. Each argument represents a different client secret to be
     * tested.
     *
     * @return a stream of arguments containing various client secrets.
     */
    static Stream<Arguments> clientSecretProvider() {
        return Stream.of(Arguments.of("{noop}secret"),
                Arguments.of("{bcrypt}$2a$10$PE5VkNv7q93/c43HtD/FpOV2ixhbDQ.ijfslzImHtL/YGVGYHfgZi"),
                Arguments.of("noop}secret"), Arguments.of("{noopsecret"));
    }

    /**
     * Tests the conversion of a client with various client secrets to a RegisteredClient instance. This test uses
     * parameterized inputs to verify the behavior of the RegisteredClientMapper with different client secrets.
     *
     * @param clientSecret the client secret to be tested.
     */
    
    @ParameterizedTest 
    @MethodSource("clientSecretProvider")
    void testToRegisteredClientWithVariousClientSecrets(String clientSecret) {
        RegisteredClientDetails registeredClientDetails = getClient();
        registeredClientDetails.setClientSecret(clientSecret);
        RegisteredClient registeredClient = registeredClientMapper.toRegisteredClient(registeredClientDetails);
        assert registeredClient != null;
        assertEquals("testClientId", registeredClient.getClientId());
    }

}