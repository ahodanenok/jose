package ahodanenok.jose.jwe.algorithm;

import ahodanenok.jose.jwe.JweJoseHeader;

public interface JweKeyAlgorithm {

    String getName();

    KeyManagementMode getKeyManagementMode();

    Object getKey(JweJoseHeader params);

    byte[] encryptKey(Object key, JweJoseHeader params);

    Object decryptKey(byte[] key, String keyAlgorithmName, JweJoseHeader params);
}
