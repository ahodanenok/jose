package ahodanenok.jose.jwe;

class JweHeaderUnion implements JweJoseHeader {

    private final JweHeader a;
    private final JweHeader b;

    JweHeaderUnion(JweHeader a, JweHeader b) {
        this.a = a;
        this.b = b;
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

        return (T) value;
    }
}
