package ahodanenok.jose.jws;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;

import ahodanenok.jose.common.Base64Url;
import ahodanenok.jose.common.JsonConverter;
import ahodanenok.jose.jws.algorithm.JwsAlgorithm;

public final class JwsBuilder {

    private static final byte[] EMPTY_PAYLOAD = new byte[0];

    private byte[] payload;
    List<JoseParams> joseParams = new ArrayList<>();
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
        if (joseParams.size() == 0) {
            throw new IllegalStateException("Header parameter 'alg' must be present");
        } else if (joseParams.size() == 1) {
            return createOneSignature();
        } else {
           return createMultipleSignatures();
        }
    }

    private Jws createOneSignature() {
        byte[] payloadUsed = payload != null ? payload : EMPTY_PAYLOAD;
        String payloadEncoded = Base64Url.encode(payloadUsed, false);
        JwsHeader protectedHeaderUsed = joseParams.get(0).protectedHeader;
        JwsHeader unprotectedHeaderUsed = joseParams.get(0).unprotectedHeader;
        String protectedHeaderEncoded = Base64Url.encode(
            jsonConverter.convert(protectedHeaderUsed.parameters)
                .getBytes(StandardCharsets.UTF_8),
            false);
        byte[] signature = computeSignature(
                new JwsJoseHeaderUnion(protectedHeaderUsed, unprotectedHeaderUsed),
                protectedHeaderEncoded, payloadEncoded);
        String serializedForm = null;
        if (serialization != null) { // todo: compact by default?
            serializedForm = switch (serialization) {
                case COMPACT -> serializeCompact(
                    payloadEncoded,
                    protectedHeaderEncoded,
                    signature);
                case JSON -> serializeJson(
                    payloadEncoded,
                    List.of(protectedHeaderEncoded),
                    List.of(signature));
                case JSON_FLAT -> serializeJsonFlat(
                    payloadEncoded,
                    protectedHeaderEncoded,
                    signature);
            };
        }

        return new JwsOneSignature(
            payloadUsed,
            protectedHeaderUsed,
            unprotectedHeaderUsed,
            signature,
            serializedForm);
    }

    private Jws createMultipleSignatures() {
        byte[] payloadUsed = payload != null ? payload : EMPTY_PAYLOAD;
        String payloadEncoded = Base64Url.encode(payloadUsed, false);
        List<JwsHeader> protectedHeadersUsed = new ArrayList<>();
        List<JwsHeader> unprotectedHeadersUsed = new ArrayList<>();
        List<String> protectedHeadersEncoded = new ArrayList<>(joseParams.size());
        List<byte[]> signatures = new ArrayList<>(joseParams.size());
        for (int i = 0; i < joseParams.size(); i++) {
            JoseParams params = joseParams.get(i);

            JwsHeader protectedHeaderUsed = params.protectedHeader;
            protectedHeadersUsed.add(protectedHeaderUsed);
            String protectedHeaderEncoded = "";
            if (protectedHeaderUsed != null) {
                protectedHeaderEncoded = Base64Url.encode(
                    jsonConverter.convert(protectedHeaderUsed.parameters)
                        .getBytes(StandardCharsets.UTF_8),
                    false);
            }
            protectedHeadersEncoded.add(protectedHeaderEncoded);

            JwsHeader unprotectedHeaderUsed = params.unprotectedHeader;
            unprotectedHeadersUsed.add(unprotectedHeaderUsed);

            signatures.add(computeSignature(
                new JwsJoseHeaderUnion(protectedHeaderUsed, unprotectedHeaderUsed),
                protectedHeaderEncoded, payloadEncoded));
        }

        String serializedForm = null;
        if (serialization != null) { // todo: compact by default?
            serializedForm = switch (serialization) {
                case COMPACT -> throw new JwsException(
                    "Compact representation doesn't support multiple signatures");
                case JSON -> serializeJson(
                    payloadEncoded, protectedHeadersEncoded, signatures);
                case JSON_FLAT -> throw new JwsException(
                    "Json flattened representation doesn't support multiple signatures");
            };
        }

        return new JwsMultipleSignatures(
            payloadUsed,
            protectedHeadersUsed,
            unprotectedHeadersUsed,
            signatures,
            serializedForm
        );
    }

    private byte[] computeSignature(
            JwsJoseHeader joseHeader,
            String encodedProtectedHeader,
            String encodedPayload) {
        String algorithmName = joseHeader.getAlgorithm();
        if (algorithmName == null) {
            throw new IllegalStateException(
                "Header parameter 'alg' must be present");
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
        if (joseParams.get(0).unprotectedHeader != null) {
            throw new IllegalStateException(
                "Unprotected header must not be present in the jws compact representation");
        }

        return encodedProtectedHeader
            + "." + encodedPayload
            + "." + Base64Url.encode(signature, false);
    }

    private String serializeJson(
            String payloadEncoded, List<String> protectedHeadersEncoded,
            List<byte[]> signatures) {
        LinkedHashMap<String, Object> obj = new LinkedHashMap<>();
        obj.put("payload", payloadEncoded);
        List<LinkedHashMap<String, Object>> signaturesArray =
            new ArrayList<>(joseParams.size());
        for (int i = 0; i < joseParams.size(); i++) {
            LinkedHashMap<String, Object> signatureObj = new LinkedHashMap<>();
            if (!protectedHeadersEncoded.get(i).isEmpty()) {
                signatureObj.put("protected", protectedHeadersEncoded.get(i));
            }
            JoseParams params = joseParams.get(i);
            if (params.unprotectedHeader != null
                    && !params.unprotectedHeader.parameters.isEmpty()) {
                if (!Collections.disjoint(
                        params.protectedHeader.parameterNames(),
                        params.unprotectedHeader.parameterNames())) {
                    throw new IllegalStateException(
                        "Header parameters names must be disjoint in protected and unprotected header");
                }

                signatureObj.put("header", params.unprotectedHeader.parameters);
            }
            signatureObj.put("signature", Base64Url.encode(signatures.get(i), false));
            signaturesArray.add(signatureObj);
        }
        obj.put("signatures", signaturesArray);

        return jsonConverter.convert(obj);
    }

    private String serializeJsonFlat(
            String payloadEncoded, String protectedHeaderEncoded, byte[] signature) {
        LinkedHashMap<String, Object> obj = new LinkedHashMap<>();
        obj.put("payload", payloadEncoded);
        if (!protectedHeaderEncoded.isEmpty()) {
            obj.put("protected", protectedHeaderEncoded);
        }
        JoseParams params = joseParams.get(0);
        if (params.unprotectedHeader != null
                && !params.unprotectedHeader.parameters.isEmpty()) {
            if (!Collections.disjoint(
                    params.protectedHeader.parameterNames(),
                    params.unprotectedHeader.parameterNames())) {
                throw new IllegalStateException(
                    "Header parameters names must be disjoint in protected and unprotected header");
            }

            obj.put("header", params.unprotectedHeader.parameters);
        }
        obj.put("signature", Base64Url.encode(signature, false));

        return jsonConverter.convert(obj);
    }

    static final class JoseParams {

        final JwsHeader protectedHeader;
        final JwsHeader unprotectedHeader;

        JoseParams(JwsHeader protectedHeader, JwsHeader unprotectedHeader) {
            this.protectedHeader = protectedHeader;
            this.unprotectedHeader = unprotectedHeader;
        }
    }
}
