package ahodanenok.jose.jwe.algorithm;

/**
 * AES GCM using 256-bit key
 */
public final class A256GCMEncryptionAlgorithm extends AGCMEncryptionAlgorithm {

    public A256GCMEncryptionAlgorithm() {
        super("A256GCM", 256);
    }

    public A256GCMEncryptionAlgorithm(String random, String provider) {
        super("A256GCM", 256, random, provider);
    }
}
