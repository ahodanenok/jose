package ahodanenok.jose.jws.algorithm;

import java.security.Key;

/**
 * HMAC using SHA-512
 */
public final class HS512Algorithm extends JwsJcaMacAlgorithm {

    static final String NAME = "HS512";

    public HS512Algorithm(Key secretKey) {
        super(NAME, "HmacSHA512", secretKey);
    }

    public HS512Algorithm(Key secretKey, String provider) {
        super(NAME, "HmacSHA512", secretKey, provider);
    }
}
