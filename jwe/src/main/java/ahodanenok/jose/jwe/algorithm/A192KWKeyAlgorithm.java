package ahodanenok.jose.jwe.algorithm;

import javax.crypto.SecretKey;

/**
 * AES Key Wrap with default initial value using 192-bit key
 */
public final class A192KWKeyAlgorithm extends JcaAesKwKeyAlgorithm {

    public A192KWKeyAlgorithm(SecretKey secretKey) {
        super("A192KW", 192, secretKey);
    }
}
