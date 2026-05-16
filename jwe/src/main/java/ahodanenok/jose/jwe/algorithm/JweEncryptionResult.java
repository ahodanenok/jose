package ahodanenok.jose.jwe.algorithm;

/**
 * The result of encryption of a plaintext
 */
public record JweEncryptionResult(

    /**
     * Encrypted plaintext
     */
    byte[] ciphertext,

    /**
     * Tag to be used for verification of the ciphertext on decryption
     * When an encryption algorithm doesn't use verification, the tag will be an empty array
     */
    byte[] authenticationTag
) { };
