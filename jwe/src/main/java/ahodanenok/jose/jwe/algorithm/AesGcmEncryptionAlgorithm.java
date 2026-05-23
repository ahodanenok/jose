package ahodanenok.jose.jwe.algorithm;

import java.security.Key;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import ahodanenok.jose.jwe.JweException;

abstract class AesGcmEncryptionAlgorithm implements JweEncryptionAlgorithm {

    private final String jweAlgorithmName;
    private final int keySize;
    private final Cipher cipher;
    private final KeyGenerator keyGenerator;
    private SecureRandom random;

    AesGcmEncryptionAlgorithm(String jweAlgorithmName, int keySize) {
        this.jweAlgorithmName = jweAlgorithmName;
        this.keySize = keySize;
        try {
            this.cipher = Cipher.getInstance("AES/GCM/NoPadding");
            this.keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new JweException("The algorithm '%s' is not supported".formatted(jweAlgorithmName), e);
        }
        this.random = new SecureRandom();
    }

    AesGcmEncryptionAlgorithm(String jweAlgorithmName, int keySize, String random, String provider) {
        this.jweAlgorithmName = jweAlgorithmName;
        this.keySize = keySize;
        try {
            this.cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
            this.keyGenerator = KeyGenerator.getInstance("AES", provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            throw new JweException("The algorithm '%s' is not supported".formatted(jweAlgorithmName), e);
        }
        try {
            this.random = SecureRandom.getInstance(random, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new JweException("SecureRandom for the algorithm '%s' not found".formatted(random), e);
        }
    }

    public final AesGcmEncryptionAlgorithm useRandom(SecureRandom random) {
        this.random = Objects.requireNonNull(random);
        return this;
    }

    @Override
    public String getName() {
        return jweAlgorithmName;
    }

    @Override
    public final Key generateKey() {
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    @Override
    public final String getKeyAlgorithmName() {
        return "AES";
    }

    @Override
    public final byte[] generateInitializationVector() {
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        return iv;
    }

    @Override
    public final JweEncryptionResult encrypt(byte[] payload, Key key, byte[] iv, byte[] aad) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, (Key) key, new GCMParameterSpec(128, iv));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new JweException("Invalid key", e);
        }
        cipher.updateAAD(aad);
        byte[] result;
        try {
            result = cipher.doFinal(payload);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new JweException("Failed to encrypt payload", e);
        }
        return new JweEncryptionResult(
            Arrays.copyOfRange(result, 0, result.length - 16),
            Arrays.copyOfRange(result, result.length - 16, result.length)
        );
    }

    @Override
    public final JweDecryptionResult decrypt(byte[] payload, Key key, byte[] iv, byte[] aad, byte[] authenticationTag) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, (Key) key, new GCMParameterSpec(128, iv));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new JweException("Invalid key", e);
        }
        cipher.updateAAD(aad);
        try {
            cipher.update(payload);
            return new JweDecryptionResult(cipher.doFinal(authenticationTag), true);
        } catch (AEADBadTagException e) {
            return new JweDecryptionResult(null, false);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new JweException("Failed to decrypt payload", e);
        }
    }
}
