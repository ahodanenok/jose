package ahodanenok.jose.jws.algorithm;

import java.security.Key;

/**
 * HMAC using SHA-256
 */
public final class HS256Algorithm extends JwsJcaMacAlgorithm {

    static final String NAME = "HS256";

    public HS256Algorithm(Key secretKey) {
        super(NAME, "HmacSHA256", secretKey);
    }

    public HS256Algorithm(Key secretKey, String provider) {
        super(NAME, "HmacSHA256", secretKey, provider);
    }
}
