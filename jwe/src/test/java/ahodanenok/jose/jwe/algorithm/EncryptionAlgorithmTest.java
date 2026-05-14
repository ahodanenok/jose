package ahodanenok.jose.jwe.algorithm;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import ahodanenok.jose.jwe.TestUtils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class EncryptionAlgorithmTest {

    @Test
    public void test_A128GCM() throws Exception {
        A128GcmEncryptionAlgorithm alg = new A128GcmEncryptionAlgorithm();

        assertEquals("A128GCM", alg.getName());
        Key generatedKey = assertInstanceOf(Key.class, alg.generateKey());
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

        DecryptionResult decryptionResult = alg.decrypt(
            encryptionResult.ciphertext(), key, iv, aad, encryptionResult.authenticationTag());
        assertEquals(true, decryptionResult.authenticated());
        assertArrayEquals(
            "Hello, world!".getBytes(StandardCharsets.UTF_8),
            decryptionResult.plaintext());
    }

    @Test
    public void test_A192GCM() throws Exception {
        A192GcmEncryptionAlgorithm alg = new A192GcmEncryptionAlgorithm();

        assertEquals("A192GCM", alg.getName());
        Key generatedKey = assertInstanceOf(Key.class, alg.generateKey());
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

        DecryptionResult decryptionResult = alg.decrypt(
            encryptionResult.ciphertext(), key, iv, aad, encryptionResult.authenticationTag());
        assertEquals(true, decryptionResult.authenticated());
        assertArrayEquals(
            "Hello, world!".getBytes(StandardCharsets.UTF_8),
            decryptionResult.plaintext());
    }

    @Test
    public void test_A256GCM() throws Exception {
        A256GcmEncryptionAlgorithm alg = new A256GcmEncryptionAlgorithm();

        assertEquals("A256GCM", alg.getName());
        Key generatedKey = assertInstanceOf(Key.class, alg.generateKey());
        assertEquals("AES", generatedKey.getAlgorithm());
        assertEquals(12, alg.generateInitializationVector().length);

        Key key = new SecretKeySpec(TestUtils.bytes(0x31, 0xde, 0x29, 0xc2, 0xd4, 0x73, 0x7b, 0xf9, 0x6d, 0xff, 0xc5, 0x26, 0xab, 0xc4, 0x4b, 0x5b, 0x45, 0x6c, 0xdc, 0x70, 0xd7, 0xad, 0xfe, 0xf6, 0x4b, 0xaa, 0x64, 0x70, 0x9d, 0x4a, 0xf3, 0xab), "AES");
        byte[] iv = TestUtils.bytes(0xdb, 0x5f, 0x0d, 0xf8, 0x90, 0xaa, 0x3a, 0x4c, 0xc6, 0xe4, 0x23, 0x23);
        byte[] aad = TestUtils.bytes(0x01, 0x02, 0x03, 0x04, 0x03, 0x02, 0x01);

        EncryptionResult encryptionResult = alg.encrypt(
            "Hello, world!".getBytes(StandardCharsets.UTF_8), key, iv, aad);
        assertArrayEquals(
            TestUtils.bytes(0xD9, 0x44, 0xDB, 0x19, 0xCF, 0xDC, 0x10, 0xAF, 0x16, 0xB4, 0xBC, 0xA9, 0xA9),
            encryptionResult.ciphertext());
        assertArrayEquals(
            TestUtils.bytes(0x36, 0x3B, 0x5D, 0x6F, 0xB8, 0x4F, 0xFB, 0x38, 0xE2, 0xFD, 0x22, 0x59, 0xF6, 0x27, 0x13, 0x07),
            encryptionResult.authenticationTag());

        DecryptionResult decryptionResult = alg.decrypt(
            encryptionResult.ciphertext(), key, iv, aad, encryptionResult.authenticationTag());
        assertEquals(true, decryptionResult.authenticated());
        assertArrayEquals(
            "Hello, world!".getBytes(StandardCharsets.UTF_8),
            decryptionResult.plaintext());
    }

    @Test
    public void test_A128CBC_HS256() {
        A128CbcHS256EncryptionAlgorithm alg = new A128CbcHS256EncryptionAlgorithm(new SecureRandom());

        assertEquals("A128CBC-HS256", alg.getName());
        Key generatedKey = assertInstanceOf(Key.class, alg.generateKey());
        assertEquals("A128CBC-HS256", generatedKey.getAlgorithm());
        assertEquals(16, alg.generateInitializationVector().length);

        // https://datatracker.ietf.org/doc/html/rfc7516#appendix-B
        Key key = new SecretKeySpec(TestUtils.bytes(4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207), "A128CBC-HS256");
        byte[] iv = TestUtils.bytes(3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101);
        byte[] aad = TestUtils.bytes(101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48);
        byte[] plaintext = TestUtils.bytes(76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112, 101, 114, 46);

        EncryptionResult encryptionResult = alg.encrypt(plaintext, key, iv, aad);
        assertArrayEquals(
            TestUtils.bytes(40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6, 75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143, 112, 56, 102),
            encryptionResult.ciphertext());
        assertArrayEquals(
            TestUtils.bytes(83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38, 194, 85),
            encryptionResult.authenticationTag());

        DecryptionResult decryptionResult = alg.decrypt(
            encryptionResult.ciphertext(), key, iv, aad, encryptionResult.authenticationTag());
        assertEquals(true, decryptionResult.authenticated());
        assertArrayEquals(plaintext, decryptionResult.plaintext());
    }

    @Test
    public void test_A192CBC_HS384() {
        A192CbcHS384EncryptionAlgorithm alg = new A192CbcHS384EncryptionAlgorithm(new SecureRandom());

        assertEquals("A192CBC-HS384", alg.getName());
        Key generatedKey = assertInstanceOf(Key.class, alg.generateKey());
        assertEquals("A192CBC-HS384", generatedKey.getAlgorithm());
        assertEquals(16, alg.generateInitializationVector().length);

        Key key = new SecretKeySpec(TestUtils.bytes(0x1e, 0xe5, 0xd7, 0xcf, 0x67, 0x8a, 0x82, 0x89, 0x4e, 0x30, 0x1e, 0x19, 0xd4, 0x4e, 0xc1, 0x0a, 0xb4, 0xd0, 0xee, 0x49, 0xd4, 0x62, 0x7c, 0xfe, 0xd7, 0xe6, 0xd8, 0x61, 0xea, 0x9f, 0xa2, 0xf9, 0x81, 0x4a, 0x94, 0x86, 0x3b, 0xf8, 0x40, 0x9f, 0x57, 0xda, 0xd2, 0x8c, 0x1d, 0x39, 0x1d, 0xa9), "A192CBC-HS384");
        byte[] iv = TestUtils.bytes(0xee, 0x2a, 0x31, 0x30, 0x0d, 0xda, 0x08, 0x33, 0xc8, 0x3c, 0xfa, 0x9e, 0xd6, 0xf4, 0x85, 0x14);
        byte[] aad = TestUtils.bytes(0x74, 0x7b, 0x0a, 0x0d, 0x8c, 0x0d, 0xe7, 0x1c);
        byte[] plaintext = "Hello, world!".getBytes(StandardCharsets.UTF_8);

        EncryptionResult encryptionResult = alg.encrypt(plaintext, key, iv, aad);
        assertArrayEquals(
            TestUtils.bytes(0x03, 0xd4, 0x62, 0x34, 0xed, 0xc2, 0x25, 0x5a, 0xd6, 0x35, 0xaa, 0xf2, 0x53, 0x61, 0xef, 0x79),
            encryptionResult.ciphertext());
        assertArrayEquals(
            TestUtils.bytes(0xe3, 0x9b, 0x1e, 0x3d, 0x09, 0xc6, 0x3e, 0x14, 0x2b, 0x8d, 0xfa, 0x60, 0xe3, 0x72, 0x57, 0x0c, 0x09, 0x09, 0x06, 0xef, 0x66, 0xcc, 0xcc, 0x42),
            encryptionResult.authenticationTag());

        DecryptionResult decryptionResult = alg.decrypt(
            encryptionResult.ciphertext(), key, iv, aad, encryptionResult.authenticationTag());
        assertEquals(true, decryptionResult.authenticated());
        assertArrayEquals(plaintext, decryptionResult.plaintext());
    }
}
