package ahodanenok.jose.jws;

/**
 * ECDSA using P-512 and SHA-512
 */
public final class ES512Algorithm extends JwsJcaSignatureAlgorithm {

    static final String NAME = "ES512";

    public ES512Algorithm() {
        super(NAME, "SHA512withECDSAinP1363Format");
    }

    public ES512Algorithm(String provider) {
        super(NAME, "SHA512withECDSAinP1363Format", provider);
    }
}
