package ahodanenok.jose.jwe.algorithm;

import java.security.Key;

public interface JweEncryptionAlgorithm {

    String getName();

    Key generateKey();

    String getKeyAlgorithmName();

    byte[] generateInitializationVector();

    JweEncryptionResult encrypt(byte[] payload, Key key, byte[] iv, byte[] aad);

    JweDecryptionResult decrypt(byte[] payload, Key key, byte[] iv, byte[] aad, byte[] authenticationTag);
}
