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
    private JwsSigner signer;
    private JsonConverter jsonConverter;

    public JwsBuilder withPayload(byte[] payload) {
        this.payload = Objects.requireNonNull(payload);
        return this;
    }

    public JwsHeaderDescription withHeader() {
        return new JwsHeaderDescription(this);
    }

    public JwsBuilder signedBy(JwsSigner signer) {
        this.signer = Objects.requireNonNull(signer);
        return this;
    }

    public JwsBuilder withJsonConverter(JsonConverter jsonConverter) {
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
                protectedHeaderUsed.asJson(jsonConverter).getBytes(StandardCharsets.UTF_8),
                false);
            JwsSigner signerUsed = signer != null ? signer : JwsSigner.getDefault();

            // todo: how to represent a jws with no signatures?
            return new JwsOneSignature(
                payloadUsed,
                protectedHeaderUsed,
                computeSignature(
                    signerUsed,
                    protectedHeaderUsed.getAlgorithm(),
                    encodedProtectedHeader,
                    encodedPayload));
        } else {
            // todo: support multiple signatures
            throw new UnsupportedOperationException();
        }
    }

    private byte[] computeSignature(
            JwsSigner signer,
            String algorithmName,
            String encodedProtectedHeader,
            String encodedPayload) {
        if (algorithmName == null) {
            throw new IllegalStateException("Header parameter 'alg' must be present");
        }

        return signer.sign(
            (encodedProtectedHeader + "." + encodedPayload).getBytes(StandardCharsets.US_ASCII),
            algorithmName);
    }
}
