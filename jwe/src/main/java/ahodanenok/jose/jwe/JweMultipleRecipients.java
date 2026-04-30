package ahodanenok.jose.jwe;

import java.util.List;

import ahodanenok.jose.common.Utils;

class JweMultipleRecipients implements Jwe {

    private final byte[] payload;
    private final JweHeader protectedHeader;
    private final JweHeader unprotectedHeader;
    private final List<JweHeader> recipientHeaders;
    private final String serializedForm;

    JweMultipleRecipients(
            byte[] payload,
            JweHeader protectedHeader,
            JweHeader unprotectedHeader,
            List<JweHeader> recipientHeaders,
            String serializedForm) {
        this.payload = payload;
        this.protectedHeader = protectedHeader;
        this.unprotectedHeader = unprotectedHeader;
        this.recipientHeaders = recipientHeaders;
        this.serializedForm = serializedForm;
    }

    @Override
    public byte[] getPayload() {
        return payload;
    }

    @Override
    public JweHeader getProtectedHeader() {
        return protectedHeader;
    }

    @Override
    public JweHeader getUnprotectedHeader() {
        return unprotectedHeader;
    }

    @Override
    public JweHeader getRecipientHeader() {
        return recipientHeaders.get(0);
    }

    @Override
    public JweHeader getRecipientHeader(int idx) {
        Utils.checkBounds(idx, 0, recipientHeaders.size());
        return recipientHeaders.get(idx);
    }

    @Override
    public int getRecipientCount() {
        return recipientHeaders.size();
    }

    @Override
    public String asString() {
        return serializedForm;
    }
}
