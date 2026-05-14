package ahodanenok.jose.jwe.algorithm;

public interface JweEncryptionAlgorithm {

    String getName();

    Object generateKey();

    byte[] generateInitializationVector();

    EncryptionResult encrypt(byte[] payload, Object key, byte[] iv, byte[] aad);

    DecryptionResult decrypt(byte[] payload, Object key, byte[] iv, byte[] aad, byte[] authenticationTag);
}
