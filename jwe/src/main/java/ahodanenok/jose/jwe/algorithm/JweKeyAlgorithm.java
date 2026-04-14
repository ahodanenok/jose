package ahodanenok.jose.jwe.algorithm;

import ahodanenok.jose.jwe.JweHeader;

public interface JweKeyAlgorithm {

    String getName();

    KeyManagementMode getKeyManagementMode();

    byte[] generateKey(JweHeader params);

    byte[] encryptKey(byte[] key, JweHeader params);

    byte[] decryptKey(byte[] key, JweHeader params);
}
