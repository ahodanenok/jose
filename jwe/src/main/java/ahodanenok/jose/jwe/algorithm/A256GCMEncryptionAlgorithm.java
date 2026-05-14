package ahodanenok.jose.jwe.algorithm;

/**
 * AES GCM using 256-bit key
 */
public final class A256GcmEncryptionAlgorithm extends AGcmEncryptionAlgorithm {

    public A256GcmEncryptionAlgorithm() {
        super("A256GCM", 256);
    }

    public A256GcmEncryptionAlgorithm(String random, String provider) {
        super("A256GCM", 256, random, provider);
    }
}
