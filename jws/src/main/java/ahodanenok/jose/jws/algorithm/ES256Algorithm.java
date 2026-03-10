package ahodanenok.jose.jws.algorithm;

/**
 * ECDSA using P-256 and SHA-256
 */
public final class ES256Algorithm extends JwsJcaSignatureAlgorithm {

    static final String NAME = "ES256";

    public ES256Algorithm() {
        super(NAME, "SHA256withECDSAinP1363Format");
    }

    public ES256Algorithm(String provider) {
        super(NAME, "SHA256withECDSAinP1363Format", provider);
    }
}
