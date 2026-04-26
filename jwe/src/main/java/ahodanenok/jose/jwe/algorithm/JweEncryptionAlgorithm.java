package ahodanenok.jose.jwe.algorithm;

import ahodanenok.jose.jwe.JweJoseHeader;

public interface JweEncryptionAlgorithm {

    String getName();

    Object generateKey(JweJoseHeader params);

    byte[] generateInitializationVector();

    EncryptionResult encrypt(byte[] payload, Object key, byte[] iv, byte[] aad, JweJoseHeader params);

    byte[] decrypt(byte[] payload, Object key, JweJoseHeader params);
}
