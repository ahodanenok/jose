package ahodanenok.jose.jwe.algorithm;

import java.security.Key;

import ahodanenok.jose.jwe.JweJoseHeader;

/**
 * The cryptographic algorithm used to encrypt or determine the value of the CEK
 * https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.1
 */
public interface JweKeyAlgorithm {

    /**
     * The name of the algorithm
     * https://datatracker.ietf.org/doc/html/rfc7518#autoid-12
     */
    String getName();

    /**
     * A method of determining the CEK value to use
     */
    KeyManagementMode getKeyManagementMode();

    /**
     * The CEK value to use for encryption
     * Only applicable for the algorithms with 'Direct Key Agreement' and 'Direct Key Agreement' key management modes
     *
     * @param joseHeader JOSE Header (https://datatracker.ietf.org/doc/html/rfc7516#section-3)
     */
    Key getContentEncryptionKey(JweJoseHeader joseHeader);

    /**
     * Encrypt the CEK
     *
     * @param key key to encrypt
     * @param joseHeader JOSE Header (https://datatracker.ietf.org/doc/html/rfc7516#section-3)
     */
    byte[] encryptKey(Key key, JweJoseHeader joseHeader);

    /**
     * Decrypt the CEK
     *
     * @param key encrypted key
     * @param keyAlgorithmName the name of the algorithm used for content encryption
     * @param joseHeader JOSE Header (https://datatracker.ietf.org/doc/html/rfc7516#section-3)
     */
    Key decryptKey(byte[] key, String keyAlgorithmName, JweJoseHeader joseHeader);
}
