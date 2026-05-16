package ahodanenok.jose.jwe.algorithm;

import javax.crypto.SecretKey;

/**
 * AES Key Wrap with default initial value using 192-bit key
 */
public final class A192KwKeyAlgorithm extends AesKwKeyAlgorithm {

    public A192KwKeyAlgorithm(SecretKey secretKey) {
        super("A192KW", 192, secretKey);
    }
}
