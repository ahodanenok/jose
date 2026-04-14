package ahodanenok.jose.jwe;

public interface Jwe {

    static JweBuilder builder() {
        return new JweBuilder();
    }

    byte[] getPayload();

    JweHeader getProtectedHeader();

    JweHeader getUnprotectedHeader();

    String asString();
}
