package ahodanenok.jose.jws;

public interface JwsAlgoritm {

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
    byte[] sign(String input);
}
