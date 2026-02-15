package ahodanenok.jose.jws;

public enum JwsSerialization {

    /**
     * JWS Compact Serialization
     * https://datatracker.ietf.org/doc/html/rfc7515#section-7.1
     */
    COMPACT,

    /**
     * General JWS JSON Serialization
     * https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.1
     */
    JSON,

    /**
     * Flattened JWS JSON Serialization
     * https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.2
     */
    JSON_FLAT;
}
