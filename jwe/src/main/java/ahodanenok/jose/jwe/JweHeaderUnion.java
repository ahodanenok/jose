package ahodanenok.jose.jwe;

class JweHeaderUnion implements JweJoseHeader {

    private final JweHeader a;
    private final JweHeader b;
    private final JweHeader c;

    JweHeaderUnion(JweHeader a, JweHeader b, JweHeader c) {
        this.a = a;
        this.b = b;
        this.c = c;
    }

    @Override
    public String getKeyAlgorithm() {
        return get(JweHeaderNames.ALGORITHM);
    }

    @Override
    public String getEncryptionAlgorithm() {
        return get(JweHeaderNames.ENCRYPTION_ALGORITHM);
    }

    @Override
    public <T> T get(String name) {
        Object value = null;
        if (a != null) {
            value = a.get(name);
        }

        if (value == null && b != null) {
            value = b.get(name);
        }

        if (value == null && c != null) {
            value = c.get(name);
        }

        return (T) value;
    }
}
