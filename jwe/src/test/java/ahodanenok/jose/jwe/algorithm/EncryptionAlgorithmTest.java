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
            "Hello, world!".getBytes(StandardCharsets.UTF_8), key, iv, aad);
        assertArrayEquals(
            TestUtils.bytes(0xF3, 0xDC, 0x1E, 0x8D, 0xDA, 0x6C, 0x70, 0x03, 0x63, 0xCB, 0xE7, 0x75, 0x46),
            encryptionResult.ciphertext());
        assertArrayEquals(
            TestUtils.bytes(0xC1, 0xA3, 0x05, 0x0D, 0x5E, 0xF6, 0x6A, 0x08, 0xC5, 0x43, 0x34, 0xFA, 0x4E, 0xA0, 0x01, 0x97),
            encryptionResult.authenticationTag());

        assertArrayEquals(
            "Hello, world!".getBytes(StandardCharsets.UTF_8),
            alg.decrypt(encryptionResult.ciphertext(), key, iv, aad, encryptionResult.authenticationTag()));
    }

    @Test
    public void test_A192GCM() throws Exception {
        A192GCMEncryptionAlgorithm alg = new A192GCMEncryptionAlgorithm();

        assertEquals("A192GCM", alg.getName());
        Key generatedKey = assertInstanceOf(Key.class, alg.generateKey(null));
        assertEquals("AES", generatedKey.getAlgorithm());
        assertEquals(12, alg.generateInitializationVector().length);

        Key key = new SecretKeySpec(TestUtils.bytes(0xb4, 0xe8, 0x5d, 0x18, 0x80, 0x0f, 0x2d, 0x43, 0xb7, 0x70, 0x49, 0x93, 0x8a, 0xc5, 0x07, 0xe4, 0xc2, 0x62, 0x86, 0xf6, 0x11, 0xc6, 0xde, 0x76), "AES");
        byte[] iv = TestUtils.bytes(0x04, 0x5f, 0xf2, 0x6a, 0xbd, 0x86, 0xb9, 0xa9, 0x7b, 0x61, 0x2e, 0x26);
        byte[] aad = TestUtils.bytes(0x01, 0x02, 0x03, 0x04, 0x03, 0x02, 0x01);

        EncryptionResult encryptionResult = alg.encrypt(
            "Hello, world!".getBytes(StandardCharsets.UTF_8), key, iv, aad);
        assertArrayEquals(
            TestUtils.bytes(0xBE, 0xC1, 0xEE, 0x28, 0x7D, 0x27, 0xC3, 0xDE, 0x67, 0x51, 0xAF, 0x26, 0x46),
            encryptionResult.ciphertext());
        assertArrayEquals(
            TestUtils.bytes(0x22, 0x34, 0x28, 0xB3, 0x37, 0xC1, 0x20, 0x0E, 0x36, 0xEF, 0x2B, 0x05, 0x42, 0x05, 0x66, 0x49),
            encryptionResult.authenticationTag());

        assertArrayEquals(
            "Hello, world!".getBytes(StandardCharsets.UTF_8),
            alg.decrypt(encryptionResult.ciphertext(), key, iv, aad, encryptionResult.authenticationTag()));
    }

    @Test
    public void test_A256GCM() throws Exception {
        A256GCMEncryptionAlgorithm alg = new A256GCMEncryptionAlgorithm();

        assertEquals("A256GCM", alg.getName());
        Key generatedKey = assertInstanceOf(Key.class, alg.generateKey(null));
        assertEquals("AES", generatedKey.getAlgorithm());
        assertEquals(12, alg.generateInitializationVector().length);

        Key key = new SecretKeySpec(TestUtils.bytes(0x31, 0xde, 0x29, 0xc2, 0xd4, 0x73, 0x7b, 0xf9, 0x6d, 0xff, 0xc5, 0x26, 0xab, 0xc4, 0x4b, 0x5b, 0x45, 0x6c, 0xdc, 0x70, 0xd7, 0xad, 0xfe, 0xf6, 0x4b, 0xaa, 0x64, 0x70, 0x9d, 0x4a, 0xf3, 0xab), "AES");
        byte[] iv = TestUtils.bytes(0xdb, 0x5f, 0x0d, 0xf8, 0x90, 0xaa, 0x3a, 0x4c, 0xc6, 0xe4, 0x23, 0x23);
        byte[] aad = TestUtils.bytes(0x01, 0x02, 0x03, 0x04, 0x03, 0x02, 0x01);

// 31de29c2d4737bf96dffc526abc44b5b456cdc70d7adfef64baa64709d4af3ab
// db5f0df890aa3a4cc6e42323
// DB5F0DF890AA3A4CC6E42323 D944DB19CFDC10AF16B4BCA9A9363B5D6FB84FFB38E2FD2259F6271307


        EncryptionResult encryptionResult = alg.encrypt(
            "Hello, world!".getBytes(StandardCharsets.UTF_8), key, iv, aad);
        assertArrayEquals(
            TestUtils.bytes(0xD9, 0x44, 0xDB, 0x19, 0xCF, 0xDC, 0x10, 0xAF, 0x16, 0xB4, 0xBC, 0xA9, 0xA9),
            encryptionResult.ciphertext());
        assertArrayEquals(
            TestUtils.bytes(0x36, 0x3B, 0x5D, 0x6F, 0xB8, 0x4F, 0xFB, 0x38, 0xE2, 0xFD, 0x22, 0x59, 0xF6, 0x27, 0x13, 0x07),
            encryptionResult.authenticationTag());

        assertArrayEquals(
            "Hello, world!".getBytes(StandardCharsets.UTF_8),
            alg.decrypt(encryptionResult.ciphertext(), key, iv, aad, encryptionResult.authenticationTag()));
    }
}
