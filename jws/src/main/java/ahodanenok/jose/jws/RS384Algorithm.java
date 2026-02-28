package ahodanenok.jose.jws;

/**
 * RSASSA-PKCS1-v1_5 using SHA-384
 */
public final class RS384Algorithm extends JwsJcaSignatureAlgorithm {

    static final String NAME = "RS384";

    public RS384Algorithm() {
        super(NAME, "SHA384withRSA");
    }

    public RS384Algorithm(String provider) {
        super(NAME, "SHA384withRSA", provider);
    }
}
