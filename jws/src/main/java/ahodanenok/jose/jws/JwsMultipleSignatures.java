package ahodanenok.jose.jws;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

class JwsMultipleSignatures implements Jws {

    private final byte[] payload;
    private final List<JwsHeader> protectedHeaders;
    private final List<byte[]> signatures;
    private final String serializedForm;

    JwsMultipleSignatures(byte[] payload, List<JwsHeader> protectedHeaders, List<byte[]> signatures, String serializedForm) {
        this.payload = Objects.requireNonNull(payload);
        this.protectedHeaders = protectedHeaders; // todo: required?
        this.signatures = signatures; // todo: required?
        this.serializedForm = serializedForm;
    }

    @Override
    public byte[] getPayload() {
        return payload;
    }

    @Override
    public JwsHeader getProtectedHeader() {
        return protectedHeaders.get(0);
    }

    @Override
    public JwsHeader getProtectedHeader(int idx) {
        return protectedHeaders.get(idx);
    }

    @Override
    public List<JwsHeader> getProtectedHeaders() {
        return Collections.unmodifiableList(protectedHeaders);
    }

    @Override
    public byte[] getSignature() {
        return signatures.get(0);
    }

    @Override
    public byte[] getSignature(int idx) {
        return signatures.get(idx);
    }

    @Override
    public int getSignatureCount() {
        return signatures.size();
    }

    @Override
    public String asString() {
        return serializedForm;
    }
}
