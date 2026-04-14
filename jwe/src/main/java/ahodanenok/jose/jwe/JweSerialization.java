package ahodanenok.jose.jwe;

public enum JweSerialization {

    /**
     * JWE Compact Serialization
     * https://datatracker.ietf.org/doc/html/rfc7516#section-7.1
     */
    COMPACT,

    /**
     * General JWE JSON Serialization Syntax
     * https://datatracker.ietf.org/doc/html/rfc7516#section-7.2.1
     */
    JSON,

    /**
     * Flattened JWE JSON Serialization Syntax
     * https://datatracker.ietf.org/doc/html/rfc7516#section-7.2.2
     */
    JSON_FLAT;
}
