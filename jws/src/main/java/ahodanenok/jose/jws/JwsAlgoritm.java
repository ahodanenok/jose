package ahodanenok.jose.jws;

public interface JwsAlgoritm {

    /**
     * No digital signature or MAC performed
     */
    public static final String NONE = NoneAlgoritm.NAME;

    /**
     * HMAC using SHA-256
     */
    public static final String HS256 = HS256Algorithm.NAME;

    /**
     * ECDSA using P-256 and SHA-256
     */
    public static final String ES256 = ES256Algorithm.NAME;

    /**
     * Get algorithm name.
     *
     * For the list of standard algorithms see https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
     */
    String getName();

    /**
     * Compute JWS Signature.
     *
     * @param input JWS Signing Input, not null
     * @return JWS Signature, never null
     */
    byte[] sign(byte[] input);

    /**
     * Verify JWS Signature.
     *
     * @param input JWS Signing Input, not null
     * @param JWS Signature for the JWS Signing Input
     * @return true - signature is valid, false otherwise
     */
    boolean verify(byte[] input, byte[] signature);
}
