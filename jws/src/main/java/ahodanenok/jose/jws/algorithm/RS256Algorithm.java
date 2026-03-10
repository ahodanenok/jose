package ahodanenok.jose.jws.algorithm;

/**
 * RSASSA-PKCS1-v1_5 using SHA-256
 */
public final class RS256Algorithm extends JwsJcaSignatureAlgorithm {

    static final String NAME = "RS256";

    public RS256Algorithm() {
        super(NAME, "SHA256withRSA");
    }

    public RS256Algorithm(String provider) {
        super(NAME, "SHA256withRSA", provider);
    }
}
