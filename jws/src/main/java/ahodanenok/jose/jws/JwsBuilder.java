package ahodanenok.jose.jws;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;

import ahodanenok.jose.common.Base64Url;
import ahodanenok.jose.common.JsonConverter;

public final class JwsBuilder {

    private static final byte[] EMPTY_PAYLOAD = new byte[0];

    private byte[] payload;
    List<JwsHeader> protectedHeaders = new ArrayList<>();
    // todo: unprotected headers
    private List<JwsAlgorithm> algorithms;
    private JsonConverter jsonConverter;
    private JwsSerialization serialization;

    public JwsBuilder withPayload(byte[] payload) {
        this.payload = Objects.requireNonNull(payload);
        return this;
    }

    public JwsHeaderDescription withHeader() {
        return new JwsHeaderDescription(this);
    }

    public JwsBuilder allowAlgorithm(JwsAlgorithm algorithm) {
        Objects.requireNonNull(algorithm);
        if (algorithms == null) {
            algorithms = List.of(algorithm);
        } else {
            if (algorithms.size() == 1) {
                algorithms = new ArrayList<>(algorithms);
            }

            algorithms.add(algorithm);
        }

        return this;
    }

    public JwsBuilder serializedAs(JwsSerialization serialization) {
        this.serialization = Objects.requireNonNull(serialization);
        return this;
    }

    public JwsBuilder useJsonConverter(JsonConverter jsonConverter) {
        this.jsonConverter = Objects.requireNonNull(jsonConverter);
        return this;
    }

    public Jws create() {
        if (protectedHeaders.size() <= 1) {
            return createOneSignature();
        } else {
           return createMultipleSignatures();
        }
    }

    private Jws createOneSignature() {
        byte[] payloadUsed = payload != null ? payload : EMPTY_PAYLOAD;
        JwsHeader protectedHeaderUsed = !protectedHeaders.isEmpty()
            ? protectedHeaders.get(0) : JwsHeader.EMPTY;

        String encodedPayload = Base64Url.encode(payloadUsed, false);
        String encodedProtectedHeader = Base64Url.encode(
            protectedHeaderUsed.asJson(jsonConverter).getBytes(StandardCharsets.UTF_8),
            false);
        byte[] signature = computeSignature(
                protectedHeaderUsed.getAlgorithm(),
                encodedProtectedHeader, encodedPayload);
        String serializedForm = null;
        if (serialization != null) { // todo: compact by default?
            serializedForm = switch (serialization) {
                case COMPACT -> serializeCompact(
                    encodedPayload, encodedProtectedHeader, signature);
                case JSON -> serializeJson(
                    encodedPayload, List.of(encodedProtectedHeader), List.of(signature));
                case JSON_FLAT -> serializeJsonFlat(
                    encodedPayload, encodedProtectedHeader, signature);
            };
        }

        // todo: how to represent a jws with no signatures?
        return new JwsOneSignature(
            payloadUsed,
            protectedHeaderUsed,
            signature,
            serializedForm);
    }

    private Jws createMultipleSignatures() {
        byte[] payloadUsed = payload != null ? payload : EMPTY_PAYLOAD;
        String payloadEncoded = Base64Url.encode(payloadUsed, false);

        List<String> protectedHeadersEncoded = new ArrayList<>(protectedHeaders.size());
        List<byte[]> signatures = new ArrayList<>(protectedHeaders.size());
        for (int i = 0; i < protectedHeaders.size(); i++) {
            JwsHeader protectedHeader = protectedHeaders.get(i);
            String protectedHeaderEncoded = Base64Url.encode(
                protectedHeader.asJson(jsonConverter).getBytes(StandardCharsets.UTF_8),
                false);
            protectedHeadersEncoded.add(protectedHeaderEncoded);
            signatures.add(computeSignature(
                protectedHeader.getAlgorithm(),
                protectedHeaderEncoded, payloadEncoded));
        }

        String serializedForm = null;
        if (serialization != null) { // todo: compact by default?
            serializedForm = switch (serialization) {
                case COMPACT -> throw new JwsException(
                    "Compact representation doesn't support multiple signatures");
                case JSON -> serializeJson(payloadEncoded, protectedHeadersEncoded, signatures);
                case JSON_FLAT -> throw new JwsException(
                    "Json flattened representation doesn't support multiple signatures");
            };
        }

        return new JwsMultipleSignatures(
            payloadUsed,
            protectedHeaders,
            signatures,
            serializedForm
        );
    }

    private byte[] computeSignature(
            String algorithmName,
            String encodedProtectedHeader,
            String encodedPayload) {
        if (algorithmName == null) {
            throw new IllegalStateException("Header parameter 'alg' must be present");
        }

        JwsAlgorithm algorithmUsed = null;
        if (algorithms != null) {
            for (JwsAlgorithm algorithm : algorithms) {
                if (algorithm.getName().equals(algorithmName)) {
                    algorithmUsed = algorithm;
                    break;
                }
            }
        }
        if (algorithmUsed == null) {
            throw new IllegalStateException(
                "Algorithm '%s' is not allowed".formatted(algorithmName));
        }

        return algorithmUsed.sign(
            (encodedProtectedHeader + "." + encodedPayload)
                .getBytes(StandardCharsets.US_ASCII));
    }

    private String serializeCompact(
            String encodedPayload, String encodedProtectedHeader, byte[] signature) {
        // todo: check unprotected header
        return encodedProtectedHeader
            + "." + encodedPayload
            + "." + Base64Url.encode(signature, false);
    }

    private String serializeJson(
            String payloadEncoded, List<String> protectedHeadersEncoded,
            List<byte[]> signatures) {
        LinkedHashMap<String, Object> obj = new LinkedHashMap<>();
        obj.put("payload", payloadEncoded);
        List<LinkedHashMap<String, Object>> signaturesArray = new ArrayList<>();
        for (int i = 0; i < protectedHeadersEncoded.size(); i++) {
            LinkedHashMap<String, Object> signatureObj = new LinkedHashMap<>();
            signatureObj.put("protected", protectedHeadersEncoded.get(i));
            // signatureObj.put("header", ...); todo: unprotected headers
            signatureObj.put("signature", Base64Url.encode(signatures.get(i), false));
            signaturesArray.add(signatureObj);
        }
        obj.put("signatures", signaturesArray);

        return jsonConverter.convert(obj);
    }

    private String serializeJsonFlat(
            String encodedPayload, String encodedProtectedHeader, byte[] signature) {
        LinkedHashMap<String, Object> obj = new LinkedHashMap<>();
        obj.put("payload", encodedPayload);
        obj.put("protected", encodedProtectedHeader);
        // todo: unprotected header
        obj.put("signature", Base64Url.encode(signature, false));

        return jsonConverter.convert(obj);
    }
}
