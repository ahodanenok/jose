package ahodanenok.jose.jwe.algorithm;

import java.security.Key;
import java.util.Objects;

import ahodanenok.jose.jwe.JweJoseHeader;

/**
 * Direct Encryption with a Shared Symmetric Key
 */
public final class DirectKeyAlgorithm implements JweKeyAlgorithm {

    private final Key key;

    public DirectKeyAlgorithm(Key key) {
        this.key = Objects.requireNonNull(key);
    }

    @Override
    public String getName() {
        return "dir";
    }

    @Override
    public KeyManagementMode getKeyManagementMode() {
        return KeyManagementMode.DIRECT_ENCRYPTION;
    }

    @Override
    public Key getContentEncryptionKey(JweJoseHeader joseHeader) {
        return key;
    }

    @Override
    public byte[] encryptKey(Key key, JweJoseHeader joseHeader) {
        // todo: impl
        return null;
    }

    @Override
    public Key decryptKey(byte[] key, String keyAlgorithmName, JweJoseHeader joseHeader) {
        // todo: impl
        return null;
    }
}
