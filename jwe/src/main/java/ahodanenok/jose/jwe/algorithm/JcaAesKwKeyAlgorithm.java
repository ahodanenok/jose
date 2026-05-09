package ahodanenok.jose.jwe.algorithm;

import java.security.Key;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import ahodanenok.jose.jwe.JweException;
import ahodanenok.jose.jwe.JweJoseHeader;

abstract class JcaAesKwKeyAlgorithm implements JweKeyAlgorithm {

    private final String jweAlgorithmName;
    private final Cipher cipher;
    private final SecretKey secretKey;

    protected JcaAesKwKeyAlgorithm(String jweAlgorithmName, int keySize, SecretKey secretKey) {
        this.jweAlgorithmName = jweAlgorithmName;
        try {
            this.cipher = Cipher.getInstance("AESWrap_" + keySize);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new JweException("The algorithm '%s' is not supported".formatted(jweAlgorithmName), e);
        }
        this.secretKey = secretKey;
    }

    @Override
    public String getName() {
        return jweAlgorithmName;
    }

    @Override
    public KeyManagementMode getKeyManagementMode() {
        return KeyManagementMode.KEY_WRAPPING;
    }

    @Override
    public Object getKey(JweJoseHeader params) {
        return null;
    }

    @Override
    public byte[] encryptKey(Object key, JweJoseHeader params) {
        try {
            cipher.init(Cipher.WRAP_MODE, secretKey);
        } catch (InvalidKeyException e) {
            throw new JweException("Failed to encrypt the key", e);
        }

        try {
            return cipher.wrap((Key) key);
        } catch (InvalidKeyException | IllegalBlockSizeException e) {
            throw new JweException("Failed to encrypt the key", e);
        }
    }

    @Override
    public Object decryptKey(byte[] key, String keyAlgorithmName, JweJoseHeader params) {
        try {
            cipher.init(Cipher.UNWRAP_MODE, secretKey);
        } catch (InvalidKeyException e) {
            throw new JweException("Failed to decrypt the key", e);
        }

        try {
            return cipher.unwrap(key, keyAlgorithmName, Cipher.SECRET_KEY);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new JweException("Failed to decrypt the key", e);
        }
    }
}
