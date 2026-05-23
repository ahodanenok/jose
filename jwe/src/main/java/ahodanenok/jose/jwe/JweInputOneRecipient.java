package ahodanenok.jose.jwe;

class JweInputOneRecipient implements JweInput {

    private final Jwe jwe;
    private final boolean valid;

    JweInputOneRecipient(Jwe jwe, boolean valid) {
        this.jwe = jwe;
        this.valid = valid;
    }

    @Override
    public boolean isValid() {
        return valid;
    }

    @Override
    public byte[] getPayload() {
        return jwe.getPayload();
    }

    @Override
    public JweHeader getProtectedHeader() {
        return jwe.getProtectedHeader();
    }

    @Override
    public JweHeader getUnprotectedHeader() {
        return jwe.getUnprotectedHeader();
    }

    @Override
    public JweHeader getRecipientHeader() {
        return jwe.getRecipientHeader();
    }

    @Override
    public JweHeader getRecipientHeader(int idx) {
        return jwe.getRecipientHeader(idx);
    }

    @Override
    public int getRecipientCount() {
        return jwe.getRecipientCount();
    }

    @Override
    public Jwe accept() {
        return jwe;
    }
}
