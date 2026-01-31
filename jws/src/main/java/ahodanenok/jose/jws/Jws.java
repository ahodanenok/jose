package ahodanenok.jose.jws;

import java.util.List;

/**
 * Representation of a valid JSON Web Signature.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7515
 */
public interface Jws {

    /**
     * Entry point for creating a new JWS.
     */
    public static JwsBuilder builder() {
        return new JwsBuilder();
    }

    /**
     * Get JWS Payload
     *
     * Get the sequence of octets secured by this JWS.
     * If the payload is empty - an empty array will be returned.
     *
     * @returns payload octets, never null
     */
    byte[] getPayload();

    /**
     * Get the first JWS Protected Header
     */
    JwsHeader getProtectedHeader();

    /**
     * Get JWS Protected Header at specified index
     *
     * @throws IllegalArgumentException if idx < 0 or idx > the number of signatures
     */
    JwsHeader getProtectedHeader(int idx);

    // todo: not sure if this method is needed
    List<JwsHeader> getProtectedHeaders();

    // todo: Object setSignature();
    // todo: Object setSignature(int idx);

    // todo: not sure if this method is needed
    // List<Object> setSignatures();

    int getSignatureCount();
}
