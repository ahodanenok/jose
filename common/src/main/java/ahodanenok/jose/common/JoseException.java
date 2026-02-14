package ahodanenok.jose.common;

public abstract class JoseException extends RuntimeException {

    public JoseException(String message) {
        super(message);
    }

    public JoseException(String message, Throwable cause) {
        super(message, cause);
    }
}
