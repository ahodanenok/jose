package ahodanenok.jose.jwe.algorithm;

/**
 * AES GCM using 192-bit key
 */
public final class A192GCMEncryptionAlgorithm extends AGCMEncryptionAlgorithm {

    public A192GCMEncryptionAlgorithm() {
        super("A192GCM", 192);
    }

    public A192GCMEncryptionAlgorithm(String random, String provider) {
        super("A192GCM", 192, random, provider);
    }
}
