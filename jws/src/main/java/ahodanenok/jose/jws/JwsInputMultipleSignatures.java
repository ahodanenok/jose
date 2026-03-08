package ahodanenok.jose.jws;

import java.util.Collections;
import java.util.List;

final class JwsInputMultipleSignatures implements JwsInput {

    private final Jws jws;
    private final List<Integer> invalidSignatures;

    JwsInputMultipleSignatures(Jws jws, List<Integer> invalidSignatures) {
        this.jws = jws;;
        this.invalidSignatures = invalidSignatures;
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
    public List<Integer> getInvalidSignatures() {
        return Collections.unmodifiableList(invalidSignatures);
    }

    @Override
    public boolean isValid() {
        return invalidSignatures.isEmpty();
    }

    @Override
    public Jws accept() {
        return jws;
    }
}
