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
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.io.FilenameUtils;
import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.KeyGenerationException;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.UUID;


import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.ECSP;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_ALIAS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_FILENAME;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_PASS;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.AuthorizationServerConstants.TENANT_KEYSTORE_TYPE;
import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.MSG_DIGEST_ALGORITHM;

/**
 * The KeyStoreConfigByJavaKeyStore class is a configuration class that uses Java KeyStore for generating RSA keys.
 */
@Configuration
public class KeyStoreConfigByJavaKeyStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreConfigByJavaKeyStore.class);

    private TenantProperties tenantProperties;

    /**
     * Constructor for KeyStoreConfigByJavaKeyStore.
     * It initializes the tenant properties using the provided TenantConfigurationService.
     *
     * @param tenantConfigurationService the service to retrieve tenant properties
     */
    @Autowired
    public KeyStoreConfigByJavaKeyStore(TenantConfigurationService tenantConfigurationService) {
        tenantProperties = tenantConfigurationService.getTenantProperties(ECSP);
    }

    /**
     * This method generates a KeyStore from a JKS file.
     * The KeyStore is built using the tenant properties to get the necessary properties for the KeyStore generation.
     * It uses a FileInputStream to read the JKS file and loads it into the KeyStore.
     *
     * @return a KeyStore object that can be used for cryptographic operations
     * @throws KeyStoreException if there is an error with the keystore
     * @throws FileNotFoundException if the JKS file is not found
     */
    @Bean
    public KeyStore generateKeyStore() throws KeyStoreException, FileNotFoundException {
        LOGGER.debug("## generateKeyStore - START");
        KeyStore keyStore = KeyStore.getInstance(tenantProperties.getKeyStore().get(TENANT_KEYSTORE_TYPE));
        FileInputStream input = new FileInputStream(FilenameUtils.getName(tenantProperties.getKeyStore()
            .get(TENANT_KEYSTORE_FILENAME)));
        try (input) {
            String keyStorePassword = tenantProperties.getKeyStore().get(TENANT_KEYSTORE_PASS);
            keyStore.load(input, keyStorePassword.toCharArray());
        } catch (Exception exception) {
            throw new KeyGenerationException(exception);
        }
        LOGGER.debug("## generateKeyStore - END");
        return keyStore;
    }

    /**
     * This method generates a KeyPair from the provided KeyStore.
     * The KeyPair is built using the public key and private key from the KeyStore.
     *
     * @param keystore the KeyStore to generate the KeyPair from
     * @param alias the alias of the KeyStore entry to use
     * @param password the password to access the KeyStore
     * @return a KeyPair object that can be used for cryptographic operations
     * @throws KeyGenerationException if there is an error generating the KeyPair
     */
    private static KeyPair getKeyPair(final KeyStore keystore,
                                      final String alias, final String password) {
        LOGGER.debug("## getKeyPair - START");
        KeyPair keyPair;
        try {
            final Key key = keystore.getKey(alias, password.toCharArray());
            final Certificate cert = keystore.getCertificate(alias);
            final PublicKey publicKey = cert.getPublicKey();
            keyPair = new KeyPair(publicKey, (PrivateKey) key);
        } catch (Exception exception) {
            throw new KeyGenerationException(exception);
        }
        LOGGER.debug("## getKeyPair - END");
        return keyPair;
    }

    /**
     * This method generates an RSAKey from the generated key pair.
     * The RSAKey is built using the public key from the key pair, the private key from the key pair,
     * a randomly generated key ID, a certificate chain from the keystore, and a SHA-256 thumbprint of the certificate.
     *
     * @return an RSAKey object that can be used for cryptographic operations
     * @throws CertificateException if there is an error with the certificate in the keystore
     * @throws KeyStoreException if there is an error with the keystore
     * @throws NoSuchAlgorithmException if the specified algorithm for the message digest does not exist
     * @throws IOException if there is an error reading from the keystore
     */
    public RSAKey generateRsaKey() throws CertificateException, KeyStoreException, NoSuchAlgorithmException,
        IOException {
        LOGGER.debug("## generateRsaKey ");
        KeyStore keystore = generateKeyStore();
        KeyPair keyPair = getKeyPair(keystore, tenantProperties.getKeyStore().get(TENANT_KEYSTORE_ALIAS),
                tenantProperties.getKeyStore().get(TENANT_KEYSTORE_PASS));
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .x509CertChain(Collections.singletonList(Base64.encode(keystore.getCertificate(
                        tenantProperties.getKeyStore().get(TENANT_KEYSTORE_ALIAS)).getEncoded())))
                .x509CertSHA256Thumbprint(Base64URL.encode(MessageDigest.getInstance(MSG_DIGEST_ALGORITHM)
                        .digest(keystore.getCertificate(tenantProperties.getKeyStore().get(TENANT_KEYSTORE_ALIAS))
                            .getEncoded())))
                .build();
    }
}