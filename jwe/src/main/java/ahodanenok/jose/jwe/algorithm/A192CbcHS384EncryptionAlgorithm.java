package ahodanenok.jose.jwe.algorithm;

import java.security.SecureRandom;

/**
 * AES_192_CBC_HMAC_SHA_384
 * https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.4
 */
public final class A192CbcHS384EncryptionAlgorithm extends ACbcHmacSha2EncryptionAlgorithm {

    public A192CbcHS384EncryptionAlgorithm(SecureRandom random) {
        super("A192CBC-HS384", "HmacSHA384", 24, 24, 24, random);
    }
}
