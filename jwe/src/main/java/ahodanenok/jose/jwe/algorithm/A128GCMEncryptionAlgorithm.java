package ahodanenok.jose.jwe.algorithm;

/**
 * AES GCM using 128-bit key
 */
public final class A128GCMEncryptionAlgorithm extends JweJcaAesGcmEncryptionAlgorithm {

    public A128GCMEncryptionAlgorithm() {
        super("A128GCM", 128);
    }

    public A128GCMEncryptionAlgorithm(String random, String provider) {
        super("A128GCM", 128, random, provider);
    }
}
