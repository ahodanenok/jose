package ahodanenok.jose.jws;

class JwsJoseHeaderUnion implements JwsJoseHeader {

    private final JwsHeader a;
    private final JwsHeader b;

    JwsJoseHeaderUnion(JwsHeader a, JwsHeader b) {
        this.a = a;
        this.b = b;
    }

    @Override
    public String getAlgorithm() {
        return get("alg");
    }

    @Override
    public <T> T get(String name) {
        T value = null;
        if (a != null) {
            value = a.get(name);
        }
        if (value != null) {
            return value;
        }

        if (b != null) {
            return b.get(name);
        } else {
            return null;
        }
    }
}
