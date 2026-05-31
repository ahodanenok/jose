package ahodanenok.jose.jwe;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.ArrayList;
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

        JweEncryptionAlgorithm encryptionAlgorithm =
            getEncryptionAlgorithm(protectedHeader.getEncryptionAlgorithm());
        Key key = determineEncryptionKey(
            encryptedKey, protectedHeader, encryptionAlgorithm);
        if (key == null) {
            return new JweInputOneRecipient(
                new JweOneRecipient(null, protectedHeader, null, null, str),
                false);
        }

        JweDecryptionResult decryptionResult = encryptionAlgorithm.decrypt(
            ciphertext, key, initializationVector,
            parts[0].getBytes(StandardCharsets.US_ASCII),
            authenticationTag);

        return new JweInputOneRecipient(
            new JweOneRecipient(
                decryptionResult.plaintext(), protectedHeader, null, null, str),
            decryptionResult.authenticated());
    }

    private JweInput parseJsonFlat(String str) {
        return null;
    }

    private JweInput parseJson(String str) {
        Map<String, Object> obj;
        try {
            obj = jsonParser.parse(str);
        } catch (Exception e) {
            throw new JweException("Invalid json representation", e);
        }

        String protectedHeaderEncoded = (String) obj.get("protected");
        byte[] initializationVector = Base64Url.decode((String) obj.get("iv"), false);
        byte[] ciphertext = Base64Url.decode((String) obj.get("ciphertext"), false);
        byte[] authenticationTag = Base64Url.decode((String) obj.get("tag"), false);

        JweEncryptionAlgorithm encryptionAlgorithmUsed = null;
        Key keyUsed = null;
        JweHeader protectedHeader = parseProtectedHeader(protectedHeaderEncoded);
        JweHeader unprotectedHeader = new JweHeader((Map<String, Object>) obj.get("unprotected"));
        List<Map<String, Object>> recipientArray = (List<Map<String, Object>>) obj.get("recipients");
        List<JweHeader> recipientHeaders = new ArrayList<>(recipientArray.size());
        boolean[] valid = new boolean[recipientArray.size()];
        for (int recipientIdx = 0; recipientIdx < recipientArray.size(); recipientIdx++) {
            Map<String, Object> recipientObj = recipientArray.get(recipientIdx);
            JweHeader recipientHeader = new JweHeader((Map<String, Object>) recipientObj.get("header"));
            recipientHeaders.add(recipientHeader);
            JweJoseHeader joseHeader = new JweHeaderUnion(
                recipientHeader, protectedHeader, unprotectedHeader);
            JweEncryptionAlgorithm encryptionAlgorithm =
                getEncryptionAlgorithm(protectedHeader.getEncryptionAlgorithm());
            if (encryptionAlgorithmUsed == null) {
                encryptionAlgorithmUsed = encryptionAlgorithm;
            } else if (!encryptionAlgorithmUsed.getName().equals(encryptionAlgorithm.getName())) {
                 throw new JweException("The recipients have different content encryption algorithms");
            }

            byte[] encryptedKey = Base64Url.decode((String) recipientObj.get("encrypted_key"), false);
            Key key = determineEncryptionKey(encryptedKey, joseHeader, encryptionAlgorithm);
            if (key == null) {
                valid[recipientIdx] = false;
                continue;
            }
            if (keyUsed == null) {
                keyUsed = key;
            } else if (!keyUsed.equals(key) && !Arrays.equals(keyUsed.getEncoded(), key.getEncoded())) {
                throw new JweException("The recipients have different content encryption keys");
            }
            valid[recipientIdx] = true;
        }

        String additionalAuthenticatedDataEncoded = (String) obj.get("aad");
        String aad = (protectedHeaderEncoded != null ? protectedHeaderEncoded : "");
        if (additionalAuthenticatedDataEncoded != null) {
            aad += "." + additionalAuthenticatedDataEncoded;
        }

        JweDecryptionResult decryptionResult = encryptionAlgorithmUsed.decrypt(
            ciphertext, keyUsed, initializationVector,
            aad.getBytes(StandardCharsets.US_ASCII),
            authenticationTag);

        return new JweInputMultipleRecipients(
            new JweMultipleRecipients(
                decryptionResult.plaintext(),
                protectedHeader,
                unprotectedHeader,
                recipientHeaders,
                str),
            valid);
    }

    private JweHeader parseProtectedHeader(String protectedHeaderEncoded) {
        if (protectedHeaderEncoded == null) {
            return null;
        }

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

    private Key determineEncryptionKey(
            byte[] encryptedKey,
            JweJoseHeader joseHeader,
            JweEncryptionAlgorithm encryptionAlgorithm) {
        try {
            JweKeyAlgorithm keyAlgorithm = getKeyAlgorithm(joseHeader.getKeyAlgorithm());
            return switch (keyAlgorithm.getKeyManagementMode()) {
                case KEY_ENCRYPTION, KEY_WRAPPING, KEY_AGREEMENT_WITH_KEY_WRAPPING ->
                    keyAlgorithm.decryptKey(
                        encryptedKey,
                        encryptionAlgorithm.getKeyAlgorithmName(),
                        joseHeader);
                case DIRECT_ENCRYPTION, DIRECT_KEY_AGREEMENT ->
                    keyAlgorithm.getContentEncryptionKey(joseHeader);
            };
        } catch (JweException e) {
            e.printStackTrace();
            return null;
        }
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
