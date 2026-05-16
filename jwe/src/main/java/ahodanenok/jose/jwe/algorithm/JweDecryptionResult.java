package ahodanenok.jose.jwe.algorithm;

/**
 * The result of decryption and verifiation of a ciphertext
 */
public record JweDecryptionResult(

    /**
     * Decrypted ciphertext
     */
    byte[] plaintext,

    /**
     * The result of verification of a ciphertext
     * When true, plaintext is authentic and can be used, otherwise plaintext content is undefined
     */
    boolean authenticated
) { };
