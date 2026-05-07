package ahodanenok.jose.jwe.algorithm;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

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

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
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

    @Test
    public  void test_RSA_OAEP() throws Exception {
        RsaOaepKeyAlgorithm alg = new RsaOaepKeyAlgorithm();

        assertEquals("RSA-OAEP", alg.getName());
        assertEquals(null, alg.getKey(null));
        assertEquals(KeyManagementMode.KEY_ENCRYPTION, alg.getKeyManagementMode());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
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

    @Test
    public  void test_RSA_OAEP_256() throws Exception {
        RsaOaep256KeyAlgorithm alg = new RsaOaep256KeyAlgorithm();

        assertEquals("RSA-OAEP-256", alg.getName());
        assertEquals(null, alg.getKey(null));
        assertEquals(KeyManagementMode.KEY_ENCRYPTION, alg.getKeyManagementMode());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        KeyGenerator secretKeyGenerator = KeyGenerator.getInstance("AES");
        secretKeyGenerator.init(128);
        Key secretKey = secretKeyGenerator.generateKey();

        alg.encryptWithPublicKey(keyPair.getPublic());
        byte[] encryptedKey = alg.encryptKey(secretKey, null);
        cipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate(), new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        assertEquals(secretKey, cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY));

        alg.decryptWithPrivateKey(keyPair.getPrivate());
        assertEquals(secretKey, alg.decryptKey(encryptedKey, "AES", null));
    }
}
