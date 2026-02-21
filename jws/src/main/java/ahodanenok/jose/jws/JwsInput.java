package ahodanenok.jose.jws;

public final class JwsInput {

    private final Jws jws;
    private final boolean valid;

    JwsInput(Jws jws, boolean valid) {
        this.jws = jws;;
        this.valid = valid;
    }

    public byte[] getPayload() {
        return jws.getPayload();
    }

    public JwsHeader getProtectedHeader() {
        return jws.getProtectedHeader();
    }

    public byte[] getSignature() {
        return jws.getSignature();
    }

    public boolean isValid() {
        return valid;
    }

    public Jws accept() {
        return jws;
    }
}
