package ahodanenok.jose.jwe;

import ahodanenok.jose.common.JoseException;

public class JweException extends JoseException {

    public JweException(String message) {
        super(message);
    }

    public JweException(String message, Throwable cause) {
        super(message, cause);
    }
}
