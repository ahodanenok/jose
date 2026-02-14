package ahodanenok.jose.jws;

import ahodanenok.jose.common.JoseException;

public class JwsException extends JoseException {

    public JwsException(String message) {
        super(message);
    }

    public JwsException(String message, Throwable cause) {
        super(message, cause);
    }
}
