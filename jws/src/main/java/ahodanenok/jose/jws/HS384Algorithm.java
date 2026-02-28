package ahodanenok.jose.jws;

import java.security.Key;

/**
 * HMAC using SHA-384
 */
public final class HS384Algorithm extends JwsJcaMacAlgorithm {

    static final String NAME = "HS384";

    public HS384Algorithm(Key secretKey) {
        super(NAME, "HmacSHA384", secretKey);
    }

    public HS384Algorithm(Key secretKey, String provider) {
        super(NAME, "HmacSHA384", secretKey, provider);
    }
}
