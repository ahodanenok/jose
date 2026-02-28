package ahodanenok.jose.jws;

/**
 * RSASSA-PKCS1-v1_5 using SHA-512
 */
public final class RS512Algorithm extends JwsJcaSignatureAlgorithm {

    static final String NAME = "RS512";

    public RS512Algorithm() {
        super(NAME, "SHA512withRSA");
    }

    public RS512Algorithm(String provider) {
        super(NAME, "SHA512withRSA", provider);
    }
}
