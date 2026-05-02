package ahodanenok.jose.jwe.algorithm;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.junit.jupiter.api.Test;

import ahodanenok.jose.jwe.TestUtils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class KeyAlgorithmTest {

    @Test
    public void test_RSA1_5() throws Exception {
        RsaPkcs1KeyAlgorithm alg = new RsaPkcs1KeyAlgorithm();

        assertEquals("RSA1_5", alg.getName());
        assertEquals(null, alg.getKey(null));
        assertEquals(KeyManagementMode.KEY_ENCRYPTION, alg.getKeyManagementMode());

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);
        KeyPair keyPair = keyGenerator.generateKeyPair();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        KeyGenerator secretKeyGenerator = KeyGenerator.getInstance("AES");
        secretKeyGenerator.init(128);
        Key secretKey = secretKeyGenerator.generateKey();

        alg.encryptWithPublicKey(keyPair.getPublic());
        byte[] encryptedKey = alg.encryptKey(secretKey, null);
        cipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
        assertEquals(secretKey, cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY));

        alg.decryptWithPrivateKey(keyPair.getPrivate());
        assertEquals(secretKey, alg.decryptKey(encryptedKey, "AES", null));
    }
}
