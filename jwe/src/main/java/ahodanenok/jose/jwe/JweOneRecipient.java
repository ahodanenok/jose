package ahodanenok.jose.jwe;

class JweOneRecipient implements Jwe {

    private final byte[] payload;
    private final JweHeader protectedHeader;
    private final JweHeader unprotectedHeader;
    private final String serializedForm;

    JweOneRecipient(
            byte[] payload,
            JweHeader protectedHeader,
            JweHeader unprotectedHeader,
            String serializedForm) {
        this.payload = payload;
        this.protectedHeader = protectedHeader;
        this.unprotectedHeader = unprotectedHeader;
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
    public String asString() {
        return serializedForm;
    }
}
