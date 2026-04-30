package ahodanenok.jose.jws;

import java.util.List;

import ahodanenok.jose.common.Utils;

class JwsMultipleSignatures implements Jws {

    private final byte[] payload;
    private final List<JwsHeader> protectedHeaders;
    private final List<JwsHeader> unprotectedHeaders;
    private final List<byte[]> signatures;
    private final String serializedForm;

    JwsMultipleSignatures(
            byte[] payload,
            List<JwsHeader> protectedHeaders,
            List<JwsHeader> unprotectedHeaders,
            List<byte[]> signatures,
            String serializedForm) {
        this.payload = payload;
        this.protectedHeaders = protectedHeaders;
        this.unprotectedHeaders = unprotectedHeaders;
        this.signatures = signatures;
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
        Utils.checkBounds(idx, 0, protectedHeaders.size());
        return protectedHeaders.get(idx);
    }

    @Override
    public JwsHeader getUnprotectedHeader() {
        return unprotectedHeaders.get(0);
    }

    @Override
    public JwsHeader getUnprotectedHeader(int idx) {
        Utils.checkBounds(idx, 0, protectedHeaders.size());
        return unprotectedHeaders.get(idx);
    }

    @Override
    public byte[] getSignature() {
        return signatures.get(0);
    }

    @Override
    public byte[] getSignature(int idx) {
        Utils.checkBounds(idx, 0, protectedHeaders.size());
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
