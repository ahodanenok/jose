package ahodanenok.jose.jwe.algorithm;

/**
 * AES GCM using 192-bit key
 */
public final class A192GcmEncryptionAlgorithm extends AesGcmEncryptionAlgorithm {

    public A192GcmEncryptionAlgorithm() {
        super("A192GCM", 192);
    }

    public A192GcmEncryptionAlgorithm(String random, String provider) {
        super("A192GCM", 192, random, provider);
    }
}
