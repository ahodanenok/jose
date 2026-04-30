package ahodanenok.jose.jws;

import java.util.List;

import ahodanenok.jose.common.Utils;

class JwsOneSignature implements Jws {

    private final byte[] payload;
    private final JwsHeader protectedHeader;
    private final JwsHeader unprotectedHeader;
    private final byte[] signature;
    private final String serializedForm;

    JwsOneSignature(
            byte[] payload,
            JwsHeader protectedHeader,
            JwsHeader unprotectedHeader,
            byte[] signature,
            String serializedForm) {
        this.payload = payload;
        this.protectedHeader = protectedHeader;
        this.unprotectedHeader = unprotectedHeader;
        this.signature = signature;
        this.serializedForm = serializedForm;
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
        Utils.checkBounds(idx, 0, 1);
        return protectedHeader;
    }

    @Override
    public JwsHeader getUnprotectedHeader() {
        return unprotectedHeader;
    }

    @Override
    public JwsHeader getUnprotectedHeader(int idx) {
        Utils.checkBounds(idx, 0, 1);
        return unprotectedHeader;
    }

    @Override
    public byte[] getSignature() {
        return signature;
    }

    @Override
    public byte[] getSignature(int idx) {
        Utils.checkBounds(idx, 0, 1);
        return signature;
    }

    @Override
    public int getSignatureCount() {
        return 1;
    }

    @Override
    public String asString() {
        return serializedForm;
    }
}
