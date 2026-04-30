package ahodanenok.jose.jwe;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Map;
import java.util.function.Consumer;

import ahodanenok.jose.common.Base64Url;
import ahodanenok.jose.common.JsonConverter;
import ahodanenok.jose.jwe.algorithm.EncryptionResult;
import ahodanenok.jose.jwe.algorithm.JweEncryptionAlgorithm;
import ahodanenok.jose.jwe.algorithm.JweKeyAlgorithm;
import ahodanenok.jose.jwe.algorithm.KeyManagementMode;

public final class JweBuilder {

    private byte[] payload;
    private JweHeader protectedHeader;
    private JweHeader unprotectedHeader;
    private List<JweHeader> recipientHeaders;
    private JweSerialization serialization;
    private JsonConverter jsonConverter;
    private List<JweKeyAlgorithm> keyAlgorithms = new ArrayList<>();
    private List<JweEncryptionAlgorithm> encryptionAlgorithms = new ArrayList<>();
    private byte[] additionalAuthenticatedData;

    public JweBuilder withPayload(byte[] payload) {
        this.payload = Objects.requireNonNull(payload);
        return this;
    }

    public JweHeaderParams withProtectedHeader() {
        return new JweHeaderParams(header -> protectedHeader = header);
    }

    public JweHeaderParams withUnprotectedHeader() {
        return new JweHeaderParams(header -> unprotectedHeader = header);
    }

    public JweRecipientParams withRecipientHeader() {
        return new JweRecipientParams();
    }

    public JweBuilder withAdditionalAuthenticatedData(byte[] additionalAuthenticatedData) {
        this.additionalAuthenticatedData = additionalAuthenticatedData;
        return this;
    }

    public JweBuilder serializedAs(JweSerialization serialization) {
        this.serialization = Objects.requireNonNull(serialization);
        return this;
    }

    public JweBuilder useJsonConverter(JsonConverter jsonConverter) {
        this.jsonConverter = Objects.requireNonNull(jsonConverter);
        return this;
    }

    public JweBuilder allowedKeyAlgorithm(JweKeyAlgorithm algorithm) {
        keyAlgorithms.add(algorithm);
        return this;
    }

    public JweBuilder allowedEncryptionAlgorithm(JweEncryptionAlgorithm algorithm) {
        encryptionAlgorithms.add(algorithm);
        return this;
    }

    public Jwe create() {
        JweHeader recipientHeader = recipientHeaders != null && !recipientHeaders.isEmpty()
            ? recipientHeaders.get(0) : null;
        JweJoseHeader joseHeader = new JweHeaderUnion(
            recipientHeader, protectedHeader, unprotectedHeader);
        JweKeyAlgorithm keyAlgorithm = getKeyAlgorithm(joseHeader);
        JweEncryptionAlgorithm encryptionAlgorithm = getEncryptionAlgorithm(joseHeader);

        KeyManagementMode keyManagementMode = keyAlgorithm.getKeyManagementMode();
        Object key = switch (keyManagementMode) {
            case KEY_WRAPPING, KEY_ENCRYPTION, KEY_AGREEMENT_WITH_KEY_WRAPPING
                -> encryptionAlgorithm.generateKey(joseHeader);
            case DIRECT_KEY_AGREEMENT, DIRECT_ENCRYPTION
                -> keyAlgorithm.getKey(joseHeader);
        };

        String encodedProtectedHeader;
        if (protectedHeader != null) {
            encodedProtectedHeader = Base64Url.encode(
                jsonConverter.convert(protectedHeader.parameters).getBytes(StandardCharsets.UTF_8),
                false);
        } else {
            encodedProtectedHeader = "";
        }

        byte[] iv = encryptionAlgorithm.generateInitializationVector();
        String encodedInitializationVector = Base64Url.encode(iv, false);

        byte[] aad;
        if (additionalAuthenticatedData != null
                && additionalAuthenticatedData.length > 0) {
            aad = (encodedProtectedHeader + "."
                    + Base64Url.encode(additionalAuthenticatedData, false))
                        .getBytes(StandardCharsets.US_ASCII);
        } else {
            aad = encodedProtectedHeader.getBytes(StandardCharsets.US_ASCII);
        }

        byte[] payloadUsed = payload;
        // todo: If a "zip" parameter was included, compress the plaintext

        EncryptionResult result = encryptionAlgorithm.encrypt(payloadUsed, key, iv, aad, joseHeader);
        String encodedCiphertext = Base64Url.encode(result.ciphertext(), false);
        String encodedAuthenticationTag = Base64Url.encode(result.authenticationTag(), false);

        if (recipientHeaders == null || recipientHeaders.size() <= 1) {
            String encodedEncryptedKey = encodeEncryptKey(key, keyAlgorithm, joseHeader);
            String serializedForm = null;
            if (serialization != null) {
                serializedForm = switch (serialization) {
                    case COMPACT -> serializeCompact(
                        encodedProtectedHeader,
                        unprotectedHeader,
                        recipientHeader,
                        encodedEncryptedKey,
                        encodedInitializationVector,
                        encodedCiphertext,
                        encodedAuthenticationTag);
                    case JSON_FLAT -> serializeJsonFlat(
                        encodedProtectedHeader,
                        unprotectedHeader,
                        recipientHeader,
                        encodedEncryptedKey,
                        encodedInitializationVector,
                        encodedCiphertext,
                        encodedAuthenticationTag);
                    case JSON -> serializeJson(
                        encodedProtectedHeader,
                        unprotectedHeader,
                        recipientHeaders,
                        List.of(encodedEncryptedKey),
                        encodedInitializationVector,
                        encodedCiphertext,
                        encodedAuthenticationTag);
                };
            }

            return new JweOneRecipient(
                payloadUsed,
                protectedHeader,
                unprotectedHeader,
                recipientHeader,
                serializedForm);
        } else {
            List<String> encodedEncryptedKeys = new ArrayList<>();
            encodedEncryptedKeys.add(encodeEncryptKey(key, keyAlgorithm, joseHeader));
            for (int i = 1; i < recipientHeaders.size(); i++) {
                joseHeader = new JweHeaderUnion(
                    recipientHeaders.get(i), protectedHeader, unprotectedHeader);
                JweKeyAlgorithm recipientKeyAlgorithm = getKeyAlgorithm(joseHeader);
                if (!isCompatibleKeyManagementMode(
                        keyManagementMode,
                        recipientKeyAlgorithm.getKeyManagementMode())) {
                    throw new JweException(
                        "Can't simultaneously encrypt CEK with algorithms '%s' and '%s'"
                            .formatted(keyAlgorithm.getName(), recipientKeyAlgorithm.getName()));
                }
                encodedEncryptedKeys.add(encodeEncryptKey(
                    key, recipientKeyAlgorithm, joseHeader));
            }

            String serializedForm = switch(serialization) {
                case COMPACT -> throw new JweException(
                    "Compact representation doesn't support multiple recipients");
                case JSON_FLAT -> throw new JweException(
                    "Json flattened representation doesn't support multiple recipients");
                case JSON -> serializeJson(
                    encodedProtectedHeader,
                    unprotectedHeader,
                    recipientHeaders,
                    encodedEncryptedKeys,
                    encodedInitializationVector,
                    encodedCiphertext,
                    encodedAuthenticationTag);
            };

            return new JweMultipleRecipients(
                payload,
                protectedHeader,
                unprotectedHeader,
                recipientHeaders,
                serializedForm);
        }
    }

    private JweKeyAlgorithm getKeyAlgorithm(JweJoseHeader joseHeader) {
        String algorithmName = joseHeader.getKeyAlgorithm();
        for (JweKeyAlgorithm algorithm : keyAlgorithms) {
            if (algorithm.getName().equals(algorithmName)) {
                return algorithm;
            }
        }

        throw new JweException("Key algorithm '%s' not found".formatted(algorithmName));
    }

    private JweEncryptionAlgorithm getEncryptionAlgorithm(JweJoseHeader joseHeader) {
        String algorithmName = joseHeader.getEncryptionAlgorithm();
        for (JweEncryptionAlgorithm algorithm : encryptionAlgorithms) {
            if (algorithm.getName().equals(algorithmName)) {
                return algorithm;
            }
        }

        throw new JweException("Encryption algorithm '%s' not found".formatted(algorithmName));
    }

    private boolean isCompatibleKeyManagementMode(KeyManagementMode a, KeyManagementMode b) {
        return a == b
            || a == KeyManagementMode.KEY_WRAPPING && b == KeyManagementMode.KEY_ENCRYPTION
            || a == KeyManagementMode.KEY_WRAPPING && b == KeyManagementMode.KEY_AGREEMENT_WITH_KEY_WRAPPING
            || a == KeyManagementMode.KEY_ENCRYPTION && b == KeyManagementMode.KEY_WRAPPING
            || a == KeyManagementMode.KEY_ENCRYPTION && b == KeyManagementMode.KEY_AGREEMENT_WITH_KEY_WRAPPING
            || a == KeyManagementMode.KEY_AGREEMENT_WITH_KEY_WRAPPING && b == KeyManagementMode.KEY_WRAPPING
            || a == KeyManagementMode.KEY_AGREEMENT_WITH_KEY_WRAPPING && b == KeyManagementMode.KEY_ENCRYPTION;
    }

    private String serializeCompact(
            String encodedProtectedHeader,
            JweHeader unprotectedHeader,
            JweHeader recipientHeader,
            String encodedEncryptedKey,
            String encodedInitializationVector,
            String encodedCiphertext,
            String encodedAuthenticationTag) {
        if (unprotectedHeader != null) {
            throw new JweException(
                "Compact representation doesn't support unprotected header");
        }

        if (recipientHeader != null) {
            throw new JweException(
                "Compact representation doesn't support recipient header");
        }

        return encodedProtectedHeader
            + "." + encodedEncryptedKey
            + "." + encodedInitializationVector
            + "." + encodedCiphertext
            + "." + encodedAuthenticationTag;
    }

    private String serializeJsonFlat(
            String encodedProtectedHeader,
            JweHeader unprotectedHeader,
            JweHeader recipientHeader,
            String encodedEncryptedKey,
            String encodedInitializationVector,
            String encodedCiphertext,
            String encodedAuthenticationTag) {
        Map<String, Object> jwe = new LinkedHashMap<>();
        if (!encodedProtectedHeader.isEmpty()) {
            jwe.put("protected", encodedProtectedHeader);
        }
        if (unprotectedHeader != null) {
            jwe.put("unprotected", unprotectedHeader.parameters);
        }
        if (recipientHeader != null) {
            jwe.put("header", recipientHeader.parameters);
        }
        if (!encodedEncryptedKey.isEmpty()) {
            jwe.put("encrypted_key", encodedEncryptedKey);
        }
        if (additionalAuthenticatedData != null) {
            jwe.put("aad", Base64Url.encode(additionalAuthenticatedData, false));
        }
        if (!encodedInitializationVector.isEmpty()) {
            jwe.put("iv", encodedInitializationVector);
        }
        jwe.put("ciphertext", encodedCiphertext);
        if (!encodedAuthenticationTag.isEmpty()) {
            jwe.put("tag", encodedAuthenticationTag);
        }

        return jsonConverter.convert(jwe);
    }

    private String serializeJson(
            String encodedProtectedHeader,
            JweHeader unprotectedHeader,
            List<JweHeader> recipientHeaders,
            List<String> encodedEncryptedKeys,
            String encodedInitializationVector,
            String encodedCiphertext,
            String encodedAuthenticationTag) {
        Map<String, Object> jwe = new LinkedHashMap<>();
        if (!encodedProtectedHeader.isEmpty()) {
            jwe.put("protected", encodedProtectedHeader);
        }
        if (unprotectedHeader != null) {
            jwe.put("unprotected", unprotectedHeader.parameters);
        }
        List<Map<String, Object>> recipients = new ArrayList<>();
        for (int i = 0; i < recipientHeaders.size(); i++) {
            Map<String, Object> recipient = new LinkedHashMap<>();
            JweHeader recipientHeader = recipientHeaders.get(i);
            if (recipientHeader != null) {
                recipient.put("header", recipientHeader.parameters);
            }
            String encodedEncryptedKey = encodedEncryptedKeys.get(i);
            if (!encodedEncryptedKey.isEmpty()) {
                recipient.put("encrypted_key", encodedEncryptedKey);
            }
            recipients.add(recipient);
        }
        jwe.put("recipients", recipients);
        if (additionalAuthenticatedData != null) {
            jwe.put("aad", Base64Url.encode(additionalAuthenticatedData, false));
        }
        if (!encodedInitializationVector.isEmpty()) {
            jwe.put("iv", encodedInitializationVector);
        }
        jwe.put("ciphertext", encodedCiphertext);
        if (!encodedAuthenticationTag.isEmpty()) {
            jwe.put("tag", encodedAuthenticationTag);
        }

        return jsonConverter.convert(jwe);
    }

    private String encodeEncryptKey(Object key, JweKeyAlgorithm keyAlgorithm, JweJoseHeader joseHeader) {
        KeyManagementMode keyManagementMode = keyAlgorithm.getKeyManagementMode();
        if (keyManagementMode == KeyManagementMode.KEY_WRAPPING
                || keyManagementMode == KeyManagementMode.KEY_ENCRYPTION
                || keyManagementMode == KeyManagementMode.KEY_AGREEMENT_WITH_KEY_WRAPPING) {
            return Base64Url.encode(keyAlgorithm.encryptKey(key, joseHeader), false);
        } else {
            return "";
        }
    }

    public final class JweHeaderParams {

        // Use LinkedHashMap to allow generation of json with the same order of params
        private final LinkedHashMap<String, Object> params;
        private final Consumer<JweHeader> paramsConsumer;

        JweHeaderParams(Consumer<JweHeader> paramsConsumer) {
            this.params = new LinkedHashMap<>();
            this.paramsConsumer = paramsConsumer;
        }

        public JweHeaderParams param(String name, Object value) {
            // todo: value nullable?
            params.put(Objects.requireNonNull(name), value);
            return this;
        }

        public JweBuilder set() {
            // todo: invalidate to prevent reuse?
            paramsConsumer.accept(new JweHeader(params));
            return JweBuilder.this;
        }
    }

    public final class JweRecipientParams {

        // Use LinkedHashMap to allow generation of json with the same order of params
        private final LinkedHashMap<String, Object> params = new LinkedHashMap<>();

        public JweRecipientParams param(String name, Object value) {
            // todo: value nullable?
            params.put(Objects.requireNonNull(name), value);
            return this;
        }

        public JweBuilder add() {
            // todo: invalidate to prevent reuse?
            if (recipientHeaders == null) {
                recipientHeaders = new ArrayList<>();
            }
            recipientHeaders.add(new JweHeader(params));
            return JweBuilder.this;
        }
    }
}
