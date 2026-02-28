package ahodanenok.jose.jws;

import java.util.List;

final class JwsInputOneSignature implements JwsInput {

    private static final List<Integer> INVALID_EMPTY = List.of();
    private static final List<Integer> INVALID_FIRST = List.of(0);

    private final Jws jws;
    private final boolean valid;

    JwsInputOneSignature(Jws jws, boolean valid) {
        this.jws = jws;;
        this.valid = valid;
    }

    public byte[] getPayload() {
        return jws.getPayload();
    }

    public JwsHeader getProtectedHeader() {
        return jws.getProtectedHeader();
    }

    public JwsHeader getProtectedHeader(int idx) {
        return jws.getProtectedHeader(idx);
    }

    public byte[] getSignature() {
        return jws.getSignature();
    }

    public byte[] getSignature(int idx) {
        return jws.getSignature(idx);
    }

    public boolean isValid() {
        return valid;
    }

    public List<Integer> getInvalidSignatures() {
        return valid ? INVALID_EMPTY : INVALID_FIRST;
    }

    public Jws accept() {
        return jws;
    }
}
