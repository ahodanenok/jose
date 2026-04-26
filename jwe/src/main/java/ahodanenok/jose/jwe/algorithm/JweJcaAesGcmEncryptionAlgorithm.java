package ahodanenok.jose.jwe.algorithm;

import java.security.Key;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.NoSuchPaddingException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;

import ahodanenok.jose.jwe.JweException;
import ahodanenok.jose.jwe.JweJoseHeader;

abstract class JweJcaAesGcmEncryptionAlgorithm implements JweEncryptionAlgorithm {

    private final String jweAlgorithmName;
    private final int keySize;
    private final Cipher cipher;
    private final KeyGenerator keyGenerator;
    private JweRandom random;

    JweJcaAesGcmEncryptionAlgorithm(String jweAlgorithmName, int keySize) {
        this.jweAlgorithmName = jweAlgorithmName;
        this.keySize = keySize;
        try {
            this.cipher = Cipher.getInstance("AES/GCM/NoPadding");
            this.keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new JweException("The algorithm '%s' is not supported".formatted(jweAlgorithmName), e);
        }
        this.random = JweRandom.from(new SecureRandom());
    }

    JweJcaAesGcmEncryptionAlgorithm(String jweAlgorithmName, int keySize, String random, String provider) {
        this.jweAlgorithmName = jweAlgorithmName;
        this.keySize = keySize;
        try {
            this.cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
            this.keyGenerator = KeyGenerator.getInstance("AES", provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            throw new JweException("The algorithm '%s' is not supported".formatted(jweAlgorithmName), e);
        }
        try {
            this.random = JweRandom.from(SecureRandom.getInstance(random, provider));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new JweException("SecureRandom for the algorithm '%s' not found".formatted(random), e);
        }
    }

    public final JweJcaAesGcmEncryptionAlgorithm useRandom(JweRandom random) {
        this.random = Objects.requireNonNull(random);
        return this;
    }

    @Override
    public String getName() {
        return jweAlgorithmName;
    }

    @Override
    public final Object generateKey(JweJoseHeader params) {
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    @Override
    public final byte[] generateInitializationVector() {
        byte[] iv = new byte[12];
        random.randomBytes(iv);
        return iv;
    }

    @Override
    public final EncryptionResult encrypt(byte[] payload, Object key, byte[] iv, byte[] aad, JweJoseHeader params) {
        if (!(key instanceof Key)) {
            throw new JweException("Invalid key, must be an instance of java.security.Key");
        }

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
        return new EncryptionResult(
            Arrays.copyOfRange(result, 0, result.length - 16),
            Arrays.copyOfRange(result, result.length - 16, result.length)
        );
    }

    @Override
    public final byte[] decrypt(byte[] payload, Object key, JweJoseHeader params) {
        // todo: impl
        return null;
    }
}
