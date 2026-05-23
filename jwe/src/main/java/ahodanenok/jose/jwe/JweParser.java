package ahodanenok.jose.jwe;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.List;
import java.util.Map;

import ahodanenok.jose.common.Base64Url;
import ahodanenok.jose.common.JsonParser;
import ahodanenok.jose.jwe.algorithm.JweDecryptionResult;
import ahodanenok.jose.jwe.algorithm.JweEncryptionAlgorithm;
import ahodanenok.jose.jwe.algorithm.JweKeyAlgorithm;

public final class JweParser {

    public static JweParserBuilder builder() {
        return new JweParserBuilder();
    }

    private final JweSerialization serialization;
    private final List<JweKeyAlgorithm> allowedKeyAlgorithms;
    private final List<JweEncryptionAlgorithm> allowedEncryptionAlgorithms;
    private final JsonParser jsonParser;

    JweParser(
            JweSerialization serialization,
            List<JweKeyAlgorithm> allowedKeyAlgorithms,
            List<JweEncryptionAlgorithm> allowedEncryptionAlgorithms,
            JsonParser jsonParser) {
        this.serialization = serialization;
        this.allowedKeyAlgorithms = allowedKeyAlgorithms;
        this.allowedEncryptionAlgorithms = allowedEncryptionAlgorithms;
        this.jsonParser = jsonParser;
    }

    public JweInput parse(String str) {
        return switch (serialization) {
            case COMPACT -> parseCompact(str);
            case JSON_FLAT -> parseJsonFlat(str);
            case JSON -> parseJson(str);
        };
    }

    private JweInput parseCompact(String str) {
        String[] parts = str.split("\\.");
        if (parts.length != 5) {
            throw new JweException("Invalid compact representation");
        }

        JweHeader protectedHeader = parseProtectedHeader(parts[0]);
        byte[] encryptedKey = Base64Url.decode(parts[1], false);
        byte[] initializationVector = Base64Url.decode(parts[2], false);
        byte[] ciphertext = Base64Url.decode(parts[3], false);
        byte[] authenticationTag = Base64Url.decode(parts[4], false);

        JweEncryptionAlgorithm encryptionAlgorithm = getEncryptionAlgorithm(protectedHeader.getEncryptionAlgorithm());
        JweKeyAlgorithm keyAlgorithm = getKeyAlgorithm(protectedHeader.getKeyAlgorithm());
        Key key = switch (keyAlgorithm.getKeyManagementMode()) {
            case KEY_ENCRYPTION, KEY_WRAPPING, KEY_AGREEMENT_WITH_KEY_WRAPPING ->
                keyAlgorithm.decryptKey(encryptedKey, encryptionAlgorithm.getKeyAlgorithmName(), protectedHeader);
            case DIRECT_ENCRYPTION, DIRECT_KEY_AGREEMENT -> keyAlgorithm.getContentEncryptionKey(protectedHeader);
        };

        JweDecryptionResult decryptionResult = encryptionAlgorithm.decrypt(
            ciphertext, key, initializationVector, parts[0].getBytes(StandardCharsets.US_ASCII), authenticationTag);

        return new JweInputOneRecipient(
            new JweOneRecipient(decryptionResult.plaintext(), protectedHeader, null, null, str),
            decryptionResult.authenticated());
    }

    private JweInput parseJsonFlat(String str) {
        return null;
    }

    private JweInput parseJson(String str) {
        return null;
    }

    private JweHeader parseProtectedHeader(String protectedHeaderEncoded) {
        String json = new String(
            Base64Url.decode(protectedHeaderEncoded, false),
            StandardCharsets.UTF_8);

        Map<String, Object> params;
        try {
            params = jsonParser.parse(json);
        } catch (Exception e) {
            throw new JweException("Failed to parse protected header", e);
        }

        return new JweHeader(params);
    }

    private JweKeyAlgorithm getKeyAlgorithm(String algorithmName) {
        for (JweKeyAlgorithm algorithm : allowedKeyAlgorithms) {
            if (algorithm.getName().equals(algorithmName)) {
                return algorithm;
            }
        }

        throw new JweException("Key algorithm '%s' not found".formatted(algorithmName));
    }

    private JweEncryptionAlgorithm getEncryptionAlgorithm(String algorithmName) {
        for (JweEncryptionAlgorithm algorithm : allowedEncryptionAlgorithms) {
            if (algorithm.getName().equals(algorithmName)) {
                return algorithm;
            }
        }

        throw new JweException("Encryption algorithm '%s' not found".formatted(algorithmName));
    }
}
