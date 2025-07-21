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

import org.eclipse.ecsp.oauth2.server.core.config.tenantproperties.TenantProperties;
import org.eclipse.ecsp.oauth2.server.core.exception.UidamApplicationException;
import org.eclipse.ecsp.oauth2.server.core.service.TenantConfigurationService;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import static org.eclipse.ecsp.oauth2.server.core.common.constants.IgniteOauth2CoreConstants.ITERATION_COUNT;

/**
 * The AdvEncryptionStdAlgoDecryption class is a component that provides a method for decrypting an encrypted string.
 * It uses the AES encryption algorithm with GCM mode and no padding.
 */
@Component
public class AdvEncryptionStdAlgoDecryption {

    private static final String ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION_MODE = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int AES_KEY_BIT = 256;

    private final TenantConfigurationService tenantConfigurationService;

    /**
     * Constructor for AdvEncryptionStdAlgoDecryption.
     *
     * @param tenantConfigurationService the tenant configuration service
     */
    public AdvEncryptionStdAlgoDecryption(TenantConfigurationService tenantConfigurationService) {
        this.tenantConfigurationService = tenantConfigurationService;
    }

    /**
     * The decrypt method is used to decrypt an encrypted string - client secret.
     * It uses the salt and secret key from the tenantProperties to generate a SecretKey for the decryption.
     * It then uses a Cipher to decrypt the encrypted string.
     * If an exception occurs during the decryption process, it throws a UidamApplicationException with the
     * exception's message.
     *
     * @param encryptedString the encrypted string to be decrypted.
     * @return the decrypted string.
     * @throws UidamApplicationException if an exception occurs during the decryption process.
     */
    public String decrypt(String encryptedString) {
        String decryptedText = "";
        try {

         
            if (encryptedString == null) {
                return decryptedText;
            }

            // separate prefix with IV from the rest of encrypted data
            byte[] encryptedPayload = Base64.getDecoder().decode(encryptedString);
            // get back the iv and salt from the cipher text
            TenantProperties tenantProperties = tenantConfigurationService.getTenantProperties();
            String salt = tenantProperties.getClient().getSecretEncryptionSalt();
            String secretKey = tenantProperties.getClient().getSecretEncryptionKey();
            ByteBuffer bb = ByteBuffer.wrap(encryptedPayload);
            byte[] iv = new byte[IV_LENGTH_BYTE];
            bb.get(iv);
            byte[] secretSalt = new byte[salt.length()];
            bb.get(secretSalt);
            byte[] encryptedBytes = new byte[bb.remaining()];
            bb.get(encryptedBytes);

            Cipher decryptCipher = Cipher.getInstance(AES_TRANSFORMATION_MODE);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, AES_KEY_BIT);
            SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);

            decryptCipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            byte[] decryptedBytes = decryptCipher.doFinal(encryptedBytes);
            decryptedText = new String(decryptedBytes);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
                 | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                 | InvalidKeySpecException e) {
            throw new UidamApplicationException("error while decrypting secret {}" + e.getMessage());
        }

        return decryptedText;
    }

}
