package ahodanenok.jose.jwe.algorithm;

/**
 * Key Management Mode
 * A method of determining the Content Encryption Key (CEK) value to use
 */
public enum KeyManagementMode {

    /**
     * CEK value is encrypted to the intended recipient using an asymmetric encryption algorithm
     */
    KEY_ENCRYPTION,

    /**
     * CEK value is encrypted to the intended recipient using a symmetric key wrapping algorithm
     */
    KEY_WRAPPING,

    /**
     * A key agreement algorithm is used to agree upon the CEK value
     */
    DIRECT_KEY_AGREEMENT,

    /**
     * A key agreement algorithm is used to agree upon a symmetric key used to encrypt
     * the CEK value to the intended recipient using a symmetric key wrapping algorithm
     */
    KEY_AGREEMENT_WITH_KEY_WRAPPING,

    /**
     * CEK value used is the secret symmetric key value shared between the parties
     */
    DIRECT_ENCRYPTION;
}
