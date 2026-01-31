package ahodanenok.jose.jws;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class JwsBuilder {

    private static final byte[] EMPTY_PAYLOAD = new byte[0];

    private byte[] payload;
    List<JwsHeader> protectedHeaders = new ArrayList<>();
    // todo: unprotected headers

    public JwsBuilder withPayload(byte[] payload) {
        this.payload = Objects.requireNonNull(payload);
        return this;
    }

    public JwsHeaderDescription withHeader() {
        return new JwsHeaderDescription(this);
    }

    public JwsBuilder signedBy(Object signer) {
        // todo: impl
        return this;
    }

    public Jws create() {
        // todo: generate signatures
        if (protectedHeaders.size() <= 1) {
            byte[] payloadUsed = payload != null ? payload : EMPTY_PAYLOAD;
            JwsHeader protectedHeaderUsed = !protectedHeaders.isEmpty()
                ? protectedHeaders.get(0) : null; // todo: null object?

            // todo: how to represent a jws with no signatures?
            return new JwsOneSignature(
                payloadUsed,
                protectedHeaderUsed,
                null);
        } else {
            // todo: support multiple signatures
            throw new UnsupportedOperationException();
        }
    }
}
