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

    public List<Integer> getInvalidSignatures() {
        return Collections.unmodifiableList(invalidSignatures);
    }

    public boolean isValid() {
        return invalidSignatures.isEmpty();
    }

    public Jws accept() {
        return jws;
    }
}
