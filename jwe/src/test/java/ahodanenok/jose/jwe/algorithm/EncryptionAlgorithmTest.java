package ahodanenok.jose.jwe.algorithm;

import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import ahodanenok.jose.jwe.TestUtils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class EncryptionAlgorithmTest {

    @Test
    public void test_A128GCM() throws Exception {
        A128GCMEncryptionAlgorithm alg = new A128GCMEncryptionAlgorithm();

        assertEquals("A128GCM", alg.getName());
        Key generatedKey = assertInstanceOf(Key.class, alg.generateKey(null));
        assertEquals("AES", generatedKey.getAlgorithm());
        assertEquals(12, alg.generateInitializationVector().length);

        Key key = new SecretKeySpec(TestUtils.bytes(0x6c, 0xbc, 0x2a, 0xd8, 0xde, 0x20, 0xb5, 0x4f, 0x18, 0x30, 0x49, 0x98, 0x2f, 0xfe, 0x5f, 0x1e), "AES");
        byte[] iv = TestUtils.bytes(0x25, 0x1f, 0xa7, 0x24, 0xf2, 0x13, 0x1e, 0x2c, 0xd0, 0x63, 0x34, 0x6e);
        byte[] aad = TestUtils.bytes(0x01, 0x02, 0x03, 0x04, 0x3, 0x2, 0x01);

        EncryptionResult encryptionResult = alg.encrypt(
            "Hello, world!".getBytes(StandardCharsets.UTF_8), key, iv, aad, null);
        assertArrayEquals(
            TestUtils.bytes(0xF3, 0xDC, 0x1E, 0x8D, 0xDA, 0x6C, 0x70, 0x03, 0x63, 0xCB, 0xE7, 0x75, 0x46),
            encryptionResult.ciphertext());
        assertArrayEquals(
            TestUtils.bytes(0xC1, 0xA3, 0x05, 0x0D, 0x5E, 0xF6, 0x6A, 0x08, 0xC5, 0x43, 0x34, 0xFA, 0x4E, 0xA0, 0x01, 0x97),
            encryptionResult.authenticationTag());
    }
}