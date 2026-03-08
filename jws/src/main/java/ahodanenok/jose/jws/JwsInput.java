package ahodanenok.jose.jws;

import java.util.List;

/**
 * Represents a JWS parsed from one of the serializations
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7515#section-7
 */
public interface JwsInput {

    /**
     * Get JWS Payload
     *
     * Get the sequence of octets extracted from the parsed JWS
     * If the payload is empty - an empty array will be returned.
     *
     * @return payload octets, never null
     */
    byte[] getPayload();

    /**
     * Get the first parsed JWS Protected Header
     *
     * @return header or null if there is no protected header
     */
    JwsHeader getProtectedHeader();

    /**
     * Get parsed JWS Protected Header at specified index
     *
     * @return header or null if there is no protected header at specified index
     * @throws IndexOutOfBoundsException if idx < 0 or idx >= signature count
     */
    JwsHeader getProtectedHeader(int idx);

    /**
     * Get the first parsed JWS Unprotected Header
     *
     * @return header or null if there is unprotected header
     */
    JwsHeader getUnprotectedHeader();

    /**
     * Get parsed JWS Unprotected Header at specified index
     *
     * @return header or null if there is no unprotected header at specified index
     * @throws IndexOutOfBoundsException if idx < 0 or idx >= signature count
     */
    JwsHeader getUnprotectedHeader(int idx);

    /**
     * Get the first parsed JWS Signature
     * If the signature is empty - an empty array will be returned
     *
     * @return signature octers, never null
     */
    byte[] getSignature();

    /**
     * Get parsed JWS Signature at specified index
     * If the signature is empty - an empty array will be returned
     *
     * @return signature octers, never null
     * @throws IndexOutOfBoundsException if idx < 0 or idx >= signature count
     */
    byte[] getSignature(int idx);

    /**
     * Check if all signatures in the parsed JWS are valid
     */
    boolean isValid();

    /**
     * Get the indices of the invalid signatures
     * If all signatures are valid, then an empty list is returned
     *
     * @return invalid signatures' indices, never null
     */
    List<Integer> getInvalidSignatures();

    /**
     * Akcnowledge the parsed JWS as valid
     *
     * JWS can be accepted even if all the signatures are invalid,
     * but this decision is up to the application
     */
    Jws accept();
}
