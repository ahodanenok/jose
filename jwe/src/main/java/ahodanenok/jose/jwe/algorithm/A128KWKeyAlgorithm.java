package ahodanenok.jose.jwe.algorithm;

import javax.crypto.SecretKey;

/**
 * AES Key Wrap with default initial value using 128-bit key
 */
public final class A128KWKeyAlgorithm extends JcaAesKwKeyAlgorithm {

    public A128KWKeyAlgorithm(SecretKey secretKey) {
        super("A128KW", 128, secretKey);
    }
}
