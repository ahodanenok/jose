package ahodanenok.jose.jwe.algorithm;

import ahodanenok.jose.jwe.JweHeader;

public interface JweEncryptionAlgorithm {

    String getName();

    byte[] encrypt(byte[] payload, Object key, JweHeader params);

    byte[] decrypt(byte[] payload, Object key, JweHeader params);
}
