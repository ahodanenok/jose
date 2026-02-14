package ahodanenok.jose.jws;

public interface JwsAlgoritm {

    public static final String None = NoneAlgoritm.NAME;
    public static final String HS256 = HS256Algorithm.NAME;

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
     * @returns JWS Signature, never null
     */
    byte[] sign(byte[] input);
}
