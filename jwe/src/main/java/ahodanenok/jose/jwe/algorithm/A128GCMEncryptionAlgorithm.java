package ahodanenok.jose.jwe.algorithm;

/**
 * AES GCM using 128-bit key
 */
public final class A128GcmEncryptionAlgorithm extends AesGcmEncryptionAlgorithm {

    public A128GcmEncryptionAlgorithm() {
        super("A128GCM", 128);
    }

    public A128GcmEncryptionAlgorithm(String random, String provider) {
        super("A128GCM", 128, random, provider);
    }
}
