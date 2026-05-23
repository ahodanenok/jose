package ahodanenok.jose.jwe;

public interface JweInput {

    boolean isValid();

    byte[] getPayload();

    JweHeader getProtectedHeader();

    JweHeader getUnprotectedHeader();

    JweHeader getRecipientHeader();

    JweHeader getRecipientHeader(int idx);

    int getRecipientCount();

    Jwe accept();
}
