package ahodanenok.jose.jws;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ahodanenok.jose.common.Base64Url;
import ahodanenok.jose.common.JsonConverter;

public final class JwsBuilder {

    private static final byte[] EMPTY_PAYLOAD = new byte[0];

    private byte[] payload;
    List<JwsHeader> protectedHeaders = new ArrayList<>();
    // todo: unprotected headers
    private List<JwsAlgoritm> algorithms;
    private JsonConverter jsonConverter;
    private JwsSerialization serialization;

    public JwsBuilder withPayload(byte[] payload) {
        this.payload = Objects.requireNonNull(payload);
        return this;
    }

    public JwsHeaderDescription withHeader() {
        return new JwsHeaderDescription(this);
    }

    public JwsBuilder allowAlgorithm(JwsAlgoritm algorithm) {
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
        // todo: generate signatures
        if (protectedHeaders.size() <= 1) {
            byte[] payloadUsed = payload != null ? payload : EMPTY_PAYLOAD;
            JwsHeader protectedHeaderUsed = !protectedHeaders.isEmpty()
                ? protectedHeaders.get(0) : JwsHeader.EMPTY;

            String encodedPayload = Base64Url.encode(payloadUsed, false);
            String encodedProtectedHeader = Base64Url.encode(
                protectedHeaderUsed.asJson(jsonConverter)
                    .getBytes(StandardCharsets.UTF_8),
                false);
            byte[] signature = computeSignature(
                    protectedHeaderUsed.getAlgorithm(),
                    encodedProtectedHeader, encodedPayload);
            String serializedForm = null;
            if (serialization != null) { // todo: compact by default?
                serializedForm = switch (serialization) {
                    case COMPACT -> serializeCompact(
                        encodedPayload, encodedProtectedHeader, signature);
                    case JSON -> serializeJson();
                    case JSON_FLAT -> serializeJsonFlat();
                };
            }

            // todo: how to represent a jws with no signatures?
            return new JwsOneSignature(
                payloadUsed,
                protectedHeaderUsed,
                signature,
                serializedForm);
        } else {
            // todo: support multiple signatures
            throw new UnsupportedOperationException();
        }
    }

    private byte[] computeSignature(
            String algorithmName,
            String encodedProtectedHeader,
            String encodedPayload) {
        if (algorithmName == null) {
            throw new IllegalStateException("Header parameter 'alg' must be present");
        }

        JwsAlgoritm algorithmUsed = null;
        if (algorithms != null) {
            for (JwsAlgoritm algorithm : algorithms) {
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
        return encodedProtectedHeader
            + "." + encodedPayload
            + "." + Base64Url.encode(signature, false);
    }

    private String serializeJson() {
        return null; // todo: impl
    }

    private String serializeJsonFlat() {
        return null; // todo: impl
    }
}
