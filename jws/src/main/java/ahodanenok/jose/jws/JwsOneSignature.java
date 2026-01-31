package ahodanenok.jose.jws;

import java.util.List;
import java.util.Objects;

class JwsOneSignature implements Jws {

    private final byte[] payload;
    private final JwsHeader protectedHeader;
    private final Object signature;

    JwsOneSignature(byte[] payload, JwsHeader protectedHeader, Object signature) {
        this.payload = Objects.requireNonNull(payload);
        this.protectedHeader = protectedHeader; // todo: required?
        this.signature = signature; // todo: required?
    }

    @Override
    public byte[] getPayload() {
        return payload;
    }

    @Override
    public JwsHeader getProtectedHeader() {
        return protectedHeader;
    }

    @Override
    public JwsHeader getProtectedHeader(int idx) {
        if (idx == 0) {
            return protectedHeader;
        } else {
            throw new IllegalArgumentException(); // todo: error message
        }
    }

    @Override
    public List<JwsHeader> getProtectedHeaders() {
        return List.of(protectedHeader);
    }

    public int getSignatureCount() {
        // todo: no signatures?
        return 1;
    }
}
