package org.eclipse.ecsp.oauth2.server.core.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for TokenHashingUtil.
 * Ensures consistent token hashing across all components.
 */
class TokenHashingUtilTest {

    private static final String TEST_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";
    private static final String TEST_SALT = "test-salt-123";
    private static final String TEST_ALGORITHM = "SHA-256";
    private static final int HASH_FORMAT_PARTS_COUNT = 2;

    @Test
    void testHashToken_WithAllParameters() {
        String hash = TokenHashingUtil.hashToken(TEST_TOKEN, TEST_ALGORITHM, TEST_SALT);
        
        assertNotNull(hash);
        assertTrue(hash.startsWith(TEST_ALGORITHM + ":"));
        
        // Verify format: algorithm:base64Hash
        String[] parts = hash.split(":", HASH_FORMAT_PARTS_COUNT);
        assertEquals(HASH_FORMAT_PARTS_COUNT, parts.length);
        assertEquals(TEST_ALGORITHM, parts[0]);
        assertFalse(parts[1].isEmpty());
    }

    @Test
    void testHashToken_WithNullAlgorithm_UsesDefault() {
        String hash = TokenHashingUtil.hashToken(TEST_TOKEN, null, TEST_SALT);
        
        assertNotNull(hash);
        assertTrue(hash.startsWith("SHA-256:"));
    }

    @Test
    void testHashToken_WithEmptyAlgorithm_UsesDefault() {
        String hash = TokenHashingUtil.hashToken(TEST_TOKEN, "", TEST_SALT);
        
        assertNotNull(hash);
        assertTrue(hash.startsWith("SHA-256:"));
    }

    @Test
    void testHashToken_WithNullSalt_UsesEmptyString() {
        String hashWithNull = TokenHashingUtil.hashToken(TEST_TOKEN, TEST_ALGORITHM, null);
        String hashWithEmpty = TokenHashingUtil.hashToken(TEST_TOKEN, TEST_ALGORITHM, "");
        
        assertEquals(hashWithNull, hashWithEmpty);
    }

    @Test
    void testHashToken_SameInputsProduceSameHash() {
        String hash1 = TokenHashingUtil.hashToken(TEST_TOKEN, TEST_ALGORITHM, TEST_SALT);
        String hash2 = TokenHashingUtil.hashToken(TEST_TOKEN, TEST_ALGORITHM, TEST_SALT);
        
        assertEquals(hash1, hash2);
    }

    @Test
    void testHashToken_DifferentTokensProduceDifferentHashes() {
        String hash1 = TokenHashingUtil.hashToken("token1", TEST_ALGORITHM, TEST_SALT);
        String hash2 = TokenHashingUtil.hashToken("token2", TEST_ALGORITHM, TEST_SALT);
        
        assertNotEquals(hash1, hash2);
    }

    @Test
    void testHashToken_DifferentSaltsProduceDifferentHashes() {
        String hash1 = TokenHashingUtil.hashToken(TEST_TOKEN, TEST_ALGORITHM, "salt1");
        String hash2 = TokenHashingUtil.hashToken(TEST_TOKEN, TEST_ALGORITHM, "salt2");
        
        assertNotEquals(hash1, hash2);
    }

    @Test
    void testHashToken_WithNullToken_ThrowsException() {
        NullPointerException exception = assertThrows(
            NullPointerException.class,
            () -> TokenHashingUtil.hashToken(null, TEST_ALGORITHM, TEST_SALT)
        );
        
        assertTrue(exception.getMessage().contains("Token must not be null"));
    }

    @Test
    void testHashToken_WithInvalidAlgorithm_ThrowsException() {
        IllegalStateException exception = assertThrows(
            IllegalStateException.class,
            () -> TokenHashingUtil.hashToken(TEST_TOKEN, "INVALID-ALGORITHM", TEST_SALT)
        );
        
        assertTrue(exception.getMessage().contains("Hash algorithm not available"));
    }

    @Test
    void testGetDefaultHashAlgorithm() {
        assertEquals("SHA-256", TokenHashingUtil.getDefaultHashAlgorithm());
    }

    @Test
    void testHashToken_ConsistencyWithExpectedFormat() {
        // Test that the hash format matches what AuthorizationService expects
        String hash = TokenHashingUtil.hashToken(TEST_TOKEN, "SHA-256", TEST_SALT);
        
        // Verify format
        assertTrue(hash.matches("^[A-Za-z0-9-]+:[A-Za-z0-9+/=]+$"));
        
        // Verify it's not the raw token
        assertFalse(hash.contains(TEST_TOKEN));
    }

    @Test
    void testHashToken_Base64Encoding() {
        String hash = TokenHashingUtil.hashToken(TEST_TOKEN, TEST_ALGORITHM, TEST_SALT);
        String[] parts = hash.split(":", HASH_FORMAT_PARTS_COUNT);
        
        // Verify the hash part is valid Base64
        assertDoesNotThrow(() -> java.util.Base64.getDecoder().decode(parts[1]));
    }
}
