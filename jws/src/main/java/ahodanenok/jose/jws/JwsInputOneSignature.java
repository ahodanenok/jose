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

    @Override
    public byte[] getPayload() {
        return jws.getPayload();
    }

    @Override
    public JwsHeader getProtectedHeader() {
        return jws.getProtectedHeader();
    }

    @Override
    public JwsHeader getProtectedHeader(int idx) {
        return jws.getProtectedHeader(idx);
    }

    @Override
    public JwsHeader getUnprotectedHeader() {
        return jws.getUnprotectedHeader();
    }

    @Override
    public JwsHeader getUnprotectedHeader(int idx) {
        return jws.getUnprotectedHeader(idx);
    }

    @Override
    public byte[] getSignature() {
        return jws.getSignature();
    }

    @Override
    public byte[] getSignature(int idx) {
        return jws.getSignature(idx);
    }

    @Override
    public boolean isValid() {
        return valid;
    }

    @Override
    public List<Integer> getInvalidSignatures() {
        return valid ? INVALID_EMPTY : INVALID_FIRST;
    }

    @Override
    public Jws accept() {
        return jws;
    }
}
