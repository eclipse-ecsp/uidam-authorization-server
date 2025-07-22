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

package org.eclipse.ecsp.oauth2.server.core.config;

import com.nimbusds.jose.jwk.RSAKey;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.KeyGenerationException;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.BEGIN_PUBLIC_KEY;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.ECSP;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.END_PUBLIC_KEY;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_JWT_KEY_ID;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_JWT_PRIVATE_KEY;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_JWT_PUBLIC_KEY;

/**
 * The KeyStoreConfigByPubPvtKey class is a configuration class that uses a public/private key pair for generating RSA
 * keys.
 */
@Configuration
public class KeyStoreConfigByPubPvtKey {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreConfigByPubPvtKey.class);

    private TenantProperties tenantProperties;

    /**
     * Constructor for the KeyStoreConfigByPubPvtKey class.
     * It initializes the tenant properties using the provided TenantConfigurationService.
     *
     * @param tenantConfigurationService the service to retrieve tenant properties
     */
    @Autowired
    public KeyStoreConfigByPubPvtKey(TenantConfigurationService tenantConfigurationService) {
        tenantProperties = tenantConfigurationService.getTenantProperties(ECSP);
    }

    /**
     * This method generates a public RSA key from a JWT public key file.
     * It reads the JWT public key file specified in the tenant properties,
     * decodes the Base64 encoded key, and generates an RSAPublicKey instance.
     *
     * @return RSAPublicKey instance generated from the JWT public key file
     * @throws KeyGenerationException if there is an error while reading the key file or generating the public key
     */
    private RSAPublicKey generatePublicKey() {
        LOGGER.debug("## generatePublicKey - START");
        RSAPublicKey rsaPublicKey;
        try {
            String key = getFile(tenantProperties.getCert().get(TENANT_JWT_PUBLIC_KEY));
            String publicKeyPem = key.replace(BEGIN_PUBLIC_KEY, "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace(END_PUBLIC_KEY, "");
            byte[] decoded = Base64.getDecoder().decode(publicKeyPem);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception exception) {
            throw new KeyGenerationException(exception);
        }
        LOGGER.debug("## generatePublicKey - END");
        return rsaPublicKey;
    }

    /**
     * This method generates a private RSA key from a JWT private key file.
     * It reads the JWT private key file specified in the tenant properties,
     * decodes the Base64 encoded key, and generates an RSAPrivateKey instance.
     *
     * @return RSAPrivateKey instance generated from the JWT private key file
     * @throws KeyGenerationException if there is an error while reading the key file or generating the private key
     */
    private RSAPrivateKey generatePrivateKey() {
        LOGGER.debug("## generatePrivateKey - START");
        RSAPrivateKey rsaPrivateKey;
        try {
            String key = getFile(tenantProperties.getCert().get(TENANT_JWT_PRIVATE_KEY));
            String privateKeyPem = key.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");
            byte[] decoded = Base64.getDecoder().decode(privateKeyPem);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
            rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception exception) {
            throw new KeyGenerationException(exception);
        }
        LOGGER.debug("## generatePrivateKey - END");
        return rsaPrivateKey;
    }

    /**
     * This method generates an RSA key using the public and private keys.
     * It first generates a public key and a private key from JWT key files specified in the tenant properties.
     * Then, it uses these keys to generate an RSA key.
     *
     * @return RSAKey instance generated from the public and private keys
     * @throws KeyGenerationException if there is an error while generating the public key, private key, or the RSA key
     */
    @Bean
    @ConditionalOnProperty(name = "ignite.oauth2.jks-enabled", havingValue = "false")
    public RSAKey generateRsaKey() throws KeyGenerationException {
        LOGGER.debug("## generateRsaKey ");
        return new RSAKey.Builder(generatePublicKey())
            .privateKey(generatePrivateKey())
            .keyID(tenantProperties.getCert().get(TENANT_JWT_KEY_ID))
            .build();
    }

    /**
     * This method retrieves the content of a file as a string.
     * It reads the file with the given name from the classpath,
     * and returns its content as a string.
     *
     * @param fileName the name of the file to read
     * @return the content of the file as a string
     * @throws KeyGenerationException if there is an error while reading the file
     */
    private String getFile(String fileName) {
        LOGGER.debug("## getFile - START");
        Resource resource = new ClassPathResource(fileName);
        StringBuilder sb = new StringBuilder();
        try (InputStreamReader keyReader = new InputStreamReader(resource.getInputStream());
            BufferedReader reader = new BufferedReader(keyReader)) {
            String str;
            while ((str = reader.readLine()) != null) {
                sb.append(str);
            }
        } catch (Exception exception) {
            throw new KeyGenerationException(exception);
        }
        LOGGER.debug("## getFile - END");
        return sb.toString();
    }

}
