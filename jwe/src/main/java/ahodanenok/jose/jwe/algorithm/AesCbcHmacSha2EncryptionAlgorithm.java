package ahodanenok.jose.jwe.algorithm;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ahodanenok.jose.jwe.JweException;

abstract class AesCbcHmacSha2EncryptionAlgorithm implements JweEncryptionAlgorithm {

    private final String name;
    private final int keySize;     // K
    private final int encKeySize;  // ENC_KEY_LEN
    private final int macKeySize;  // MAC_KEY_LEN
    private final int authTagSize; // T_LEN
    private final Cipher cipher;
    private final Mac mac;
    private final SecureRandom random;
    private final ByteBuffer aadLengthBuffer;

    AesCbcHmacSha2EncryptionAlgorithm(String jweAlgorithmName, String jcaMacAlgorithmName, int encKeySize, int macKeySize, int authTagSize, SecureRandom random) {
        this.name = jweAlgorithmName;
        try {
            this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            this.mac = Mac.getInstance(jcaMacAlgorithmName);
        } catch(NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new JweException("The algorithm '%s' is not supported".formatted(jweAlgorithmName), e);
        }
        this.random = random;
        this.aadLengthBuffer = ByteBuffer.allocate(Long.BYTES);
        this.keySize = encKeySize + macKeySize;
        this.encKeySize = encKeySize;
        this.macKeySize = macKeySize;
        this.authTagSize = authTagSize;
    }

    @Override
    public final String getName() {
        return name;
    }

    @Override
    public final Key generateKey() {
        byte[] bytes = new byte[keySize];
        random.nextBytes(bytes);
        return new SecretKeySpec(bytes, name);
    }

    @Override
    public final String getKeyAlgorithmName() {
        return name;
    }

    @Override
    public final byte[] generateInitializationVector() {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return bytes;
    }

    @Override
    public JweEncryptionResult encrypt(byte[] payload, Key key, byte[] iv, byte[] aad) {
        byte[] keyEncoded = (key).getEncoded();
        if (keyEncoded.length != keySize) {
            throw new JweException(
                "Invalid key, expected %d bytes, got %d"
                    .formatted(keySize, keyEncoded.length));
        }

        try {
            cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(keyEncoded, macKeySize, encKeySize, "AES"),
                new IvParameterSpec(iv));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new JweException("Failed to encrypt plaintext", e);
        }
        byte[] ciphertext;
        try {
            ciphertext = cipher.doFinal(payload);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new JweException("Failed to encrypt plaintext", e);
        }

        try {
            mac.init(new SecretKeySpec(keyEncoded, 0, macKeySize, mac.getAlgorithm()));
        } catch (InvalidKeyException e) {
            throw new JweException("Failed to encrypt plaintext", e);
        }
        mac.update(aad);
        mac.update(iv);
        mac.update(ciphertext);
        aadLengthBuffer.clear();
        aadLengthBuffer.putLong(aad.length * 8L);
        mac.update(aadLengthBuffer.array());
        byte[] authenticationTag = Arrays.copyOf(mac.doFinal(), authTagSize);

        return new JweEncryptionResult(ciphertext, authenticationTag);
    }

    @Override
    public JweDecryptionResult decrypt(byte[] ciphertext, Key key, byte[] iv, byte[] aad, byte[] authenticationTag) {
        byte[] keyEncoded = key.getEncoded();
        if (keyEncoded.length != keySize) {
            // https://datatracker.ietf.org/doc/html/rfc7516#section-11.5
            keyEncoded = new byte[keySize];
            random.nextBytes(keyEncoded);
        }

        try {
            mac.init(new SecretKeySpec(keyEncoded, 0, macKeySize, mac.getAlgorithm()));
        } catch (InvalidKeyException e) {
            throw new JweException("Failed to decrypt ciphertext", e);
        }
        mac.update(aad);
        mac.update(iv);
        mac.update(ciphertext);
        aadLengthBuffer.clear();
        aadLengthBuffer.putLong(aad.length * 8L);
        mac.update(aadLengthBuffer.array());
        if (!Arrays.equals(Arrays.copyOf(mac.doFinal(), authTagSize), authenticationTag)) {
            return new JweDecryptionResult(null, false);
        };

        try {
            cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(keyEncoded, macKeySize, encKeySize, "AES"),
                new IvParameterSpec(iv));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new JweException("Failed to decrypt ciphertext", e);
        }

        try {
            return new JweDecryptionResult(cipher.doFinal(ciphertext), true);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new JweException("Failed to decrypt ciphertext", e);
        }
    }
}
