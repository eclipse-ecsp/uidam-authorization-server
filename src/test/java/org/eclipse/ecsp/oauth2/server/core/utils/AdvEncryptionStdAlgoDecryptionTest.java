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

package org.eclipse.ecsp.oauth2.server.core.utils;

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.ClientProperties;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * This class tests the functionality of the AdvEncryptionStdAlgoDecryption class.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@ActiveProfiles("test")
class AdvEncryptionStdAlgoDecryptionTest {
    @Mock
    TenantProperties tenantProperties;

    @Mock
    TenantConfigurationService tenantConfigurationService;

    @Mock
    ClientProperties clientProperties;

    private AdvEncryptionStdAlgoDecryption advEncryptionStdAlgoDecryption;

    /**
     * This method sets up the test environment before each test.
     * It initializes the mocks.
     */
    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
        
        // Set up default tenant configuration mock FIRST
        Mockito.when(tenantConfigurationService.getTenantProperties()).thenReturn(tenantProperties);
        
        // Set up default client properties mock for all tests
        Mockito.when(tenantProperties.getClient()).thenReturn(clientProperties);
        Mockito.when(clientProperties.getSecretEncryptionKey()).thenReturn("ChangeMe");
        Mockito.when(clientProperties.getSecretEncryptionSalt()).thenReturn("ChangeMe");
        
        // THEN create the instance with the properly mocked service
        advEncryptionStdAlgoDecryption = new AdvEncryptionStdAlgoDecryption(tenantConfigurationService);
    }

    /**
     * This test method tests the decrypt method of the AdvEncryptionStdAlgoDecryption class with a valid encrypted
     * string.
     * It sets up the necessary parameters and then calls the decrypt method.
     * The test asserts that the returned string is the expected decrypted string.
     */
    @Test
     void testDecrypt() {
        String secret = advEncryptionStdAlgoDecryption
            .decrypt("83aRAFlyMdDzpSc1Q2hhbmdlTWVcs1vGTDCTCvTvBWEB/vVysh2qRT1GWA0=");
        assertEquals("ChangeMe", secret);
    }

    /**
     * This test method tests the decrypt method of the AdvEncryptionStdAlgoDecryption class with a null input.
     * It sets up the necessary parameters and then calls the decrypt method.
     * The test asserts that the returned string is an empty string.
     */
    @Test
     void testDecrypt_withNull() {
        String secret = advEncryptionStdAlgoDecryption.decrypt(null);
        assertEquals("", secret);
    }

    /**
     * This test method tests the decrypt method of the AdvEncryptionStdAlgoDecryption class with an invalid salt,
     * expecting a RuntimeException.
     * It sets up the necessary parameters and then calls the decrypt method.
     * The test asserts that a RuntimeException is thrown.
     */
    @Test()
     void testDecrypt_Exception() {
        Mockito.when(clientProperties.getSecretEncryptionKey()).thenReturn("ignite_secret_key");
        Mockito.when(clientProperties.getSecretEncryptionSalt()).thenReturn("ignite_random_salt_ex");

        assertThrows(RuntimeException.class, () -> advEncryptionStdAlgoDecryption
            .decrypt("He6Z5TJwwjtI2vWxaWduaXRlX3JhbmRvbV9zYWx02l9ocZ/1OsmuPgsqDt0/C9yfYsNAsKea8g=="));
    }
}
