package ahodanenok.jose.jwe.algorithm;

import java.security.SecureRandom;

/**
 * AES_128_CBC_HMAC_SHA_256
 * https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3
 */
public final class A128CbcHS256EncryptionAlgorithm extends AesCbcHmacSha2EncryptionAlgorithm {

    public A128CbcHS256EncryptionAlgorithm(SecureRandom random) {
        super("A128CBC-HS256", "HmacSHA256", 16, 16, 16, random);
    }
}
