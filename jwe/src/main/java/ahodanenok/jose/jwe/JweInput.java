package ahodanenok.jose.jwe;

public interface JweInput {

    byte[] getPayload();

    JweHeader getProtectedHeader();

    JweHeader getUnprotectedHeader();

    JweHeader getRecipientHeader();

    JweHeader getRecipientHeader(int idx);

    /**
     * Check if the payload was successfulyl validated for the first recipient
     */
    boolean isRecipientValid();

    /**
     * Check if the payload was successfulyl validated for the recipient
     *
     * @param idx recipient index
     */
    boolean isRecipientValid(int idx);

    int getRecipientCount();

    Jwe accept();
}
