package ahodanenok.jose.jwe;

import ahodanenok.jose.common.Utils;

class JweInputMultipleRecipients implements JweInput {

    private final Jwe jwe;
    private final boolean[] valid;

    JweInputMultipleRecipients(Jwe jwe, boolean[] valid) {
        this.jwe = jwe;
        this.valid = valid;
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
    public boolean isRecipientValid() {
        return valid[0];
    }

    @Override
    public boolean isRecipientValid(int idx) {
        Utils.checkBounds(idx, 0, valid.length);
        return valid[idx];
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
