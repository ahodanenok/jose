package ahodanenok.jose.jwe.algorithm;

import javax.crypto.SecretKey;

/**
 * AES Key Wrap with default initial value using 256-bit key
 */
public final class A256KWKeyAlgorithm extends JcaAesKwKeyAlgorithm {

    public A256KWKeyAlgorithm(SecretKey secretKey) {
        super("A256KW", 256, secretKey);
    }
}
