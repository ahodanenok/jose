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
     * @return payload octets, never null
     */
    byte[] getPayload();

    /**
     * Get the first JWS Protected Header
     *
     * @return header or null if there is no protected header at specified index
     */
    JwsHeader getProtectedHeader();

    /**
     * Get JWS Protected Header at specified index
     *
     * @return header or null if there is no protected header at specified index
     * @throws IndexOutOfBoundsException if idx < 0 or idx >= signature count
     */
    JwsHeader getProtectedHeader(int idx);

    /**
     * Get the first JWS Unprotected Header
     *
     * @return header or null if there is no unprotected header at specified index
     */
    JwsHeader getUnprotectedHeader();

    /**
     * Get JWS Unprotected Header at specified index
     *
     * @return header or null if there is no unprotected header at specified index
     * @throws IndexOutOfBoundsException if idx < 0 or idx >= signature count
     */
    JwsHeader getUnprotectedHeader(int idx);

    /**
     * Get the first JWS Signature
     * If the signature is empty - an empty array will be returned
     *
     * @return signature octers, never null
     */
    byte[] getSignature();

    /**
     * Get JWS Signature at specified index
     * If the signature is empty - an empty array will be returned
     *
     * @return signature octers, never null
     * @throws IndexOutOfBoundsException if idx < 0 or idx >= signature count
     */
    byte[] getSignature(int idx);

    /**
     * Get the number of JWS Signatures
     */
    int getSignatureCount();

    /**
     * Get the serialized representation of this JWS
     *
     * @see JwsSerialization
     */
    String asString();
}
