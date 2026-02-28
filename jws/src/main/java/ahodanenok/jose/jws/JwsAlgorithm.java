package ahodanenok.jose.jws;

public interface JwsAlgorithm {

    /**
     * No digital signature or MAC performed
     */
    public static final String NONE = NoneAlgorithm.NAME;

    /**
     * HMAC using SHA-256
     */
    public static final String HS256 = HS256Algorithm.NAME;

    /**
     * HMAC using SHA-384
     */
    public static final String HS384 = HS384Algorithm.NAME;

    /**
     * HMAC using SHA-512
     */
    public static final String HS512 = HS512Algorithm.NAME;

    /**
     * ECDSA using P-256 and SHA-256
     */
    public static final String ES256 = ES256Algorithm.NAME;

    /**
     * RSASSA-PKCS1-v1_5 using SHA-256
     */
    public static final String RS256 = RS256Algorithm.NAME;

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
