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

abstract class AesKwKeyAlgorithm implements JweKeyAlgorithm {

    private final String name;
    private final Cipher cipher;
    private final SecretKey secretKey;

    protected AesKwKeyAlgorithm(
            String jweAlgorithmName, int keySize, SecretKey secretKey) {
        this.name = jweAlgorithmName;
        try {
            this.cipher = Cipher.getInstance("AESWrap_" + keySize);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new JweException("The algorithm '%s' is not supported"
                .formatted(jweAlgorithmName), e);
        }
        this.secretKey = secretKey;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public KeyManagementMode getKeyManagementMode() {
        return KeyManagementMode.KEY_WRAPPING;
    }

    @Override
    public Key getContentEncryptionKey(JweJoseHeader joseHeader) {
        return null;
    }

    @Override
    public byte[] encryptKey(Key key, JweJoseHeader joseHeader) {
        try {
            cipher.init(Cipher.WRAP_MODE, secretKey);
        } catch (InvalidKeyException e) {
            throw new JweException("Failed to encrypt the key", e);
        }

        try {
            return cipher.wrap(key);
        } catch (InvalidKeyException | IllegalBlockSizeException e) {
            throw new JweException("Failed to encrypt the key", e);
        }
    }

    @Override
    public Key decryptKey(byte[] key, String keyAlgorithmName, JweJoseHeader joseHeader) {
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
