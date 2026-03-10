package ahodanenok.jose.jws.algorithm;

/**
 * ECDSA using P-384 and SHA-384
 */
public final class ES384Algorithm extends JwsJcaSignatureAlgorithm {

    static final String NAME = "ES384";

    public ES384Algorithm() {
        super(NAME, "SHA384withECDSAinP1363Format");
    }

    public ES384Algorithm(String provider) {
        super(NAME, "SHA384withECDSAinP1363Format", provider);
    }
}
