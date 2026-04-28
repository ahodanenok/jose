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
        JweJoseHeader joseHeader = new JweHeaderUnion(protectedHeader, unprotectedHeader);
        JweKeyAlgorithm keyAlgorithm = getKeyAlgorithm(joseHeader);
        JweEncryptionAlgorithm encryptionAlgorithm = getEncryptionAlgorithm(joseHeader);

        KeyManagementMode keyManagementMode = keyAlgorithm.getKeyManagementMode();
        Object key = switch (keyManagementMode) {
            case KEY_WRAPPING, KEY_ENCRYPTION, KEY_AGREEMENT_WITH_KEY_WRAPPING
                -> encryptionAlgorithm.generateKey(joseHeader);
            case DIRECT_KEY_AGREEMENT, DIRECT_ENCRYPTION
                -> keyAlgorithm.getKey(joseHeader);
        };

        String encodedEncryptedKey;
        if (keyManagementMode == KeyManagementMode.KEY_WRAPPING
                || keyManagementMode == KeyManagementMode.KEY_ENCRYPTION
                || keyManagementMode == KeyManagementMode.KEY_AGREEMENT_WITH_KEY_WRAPPING) {
            encodedEncryptedKey = Base64Url.encode(
                keyAlgorithm.encryptKey(key, joseHeader), false);
        } else {
            encodedEncryptedKey = "";
        }

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

        String serializedForm = null;
        if (serialization != null) {
            serializedForm = switch (serialization) {
                case COMPACT -> serializeCompact(
                    encodedProtectedHeader,
                    encodedEncryptedKey,
                    encodedInitializationVector,
                    encodedCiphertext,
                    encodedAuthenticationTag);
                case JSON_FLAT -> serializeJsonFlat(
                    encodedProtectedHeader,
                    encodedEncryptedKey,
                    encodedInitializationVector,
                    encodedCiphertext,
                    encodedAuthenticationTag);
                case JSON -> serializeJson();
            };
        }

        return new JweOneRecipient(
            payloadUsed,
            protectedHeader,
            unprotectedHeader,
            serializedForm
        );
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

    private String serializeCompact(
            String encodedProtectedHeader,
            String encodedEncryptedKey,
            String encodedInitializationVector,
            String encodedCiphertext,
            String encodedAuthenticationTag) {
        return encodedProtectedHeader
            + "." + encodedEncryptedKey
            + "." + encodedInitializationVector
            + "." + encodedCiphertext
            + "." + encodedAuthenticationTag;
    }

    private String serializeJsonFlat(
            String encodedProtectedHeader,
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

    private String serializeJson() {
        return null;
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
}
