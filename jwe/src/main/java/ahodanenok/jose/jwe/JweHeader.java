package ahodanenok.jose.jwe;

import java.util.Map;

public final class JweHeader implements JweJoseHeader {

    final Map<String, Object> parameters;

    JweHeader(Map<String, Object> parameters) {
        this.parameters = parameters;
    }

    @Override
    public String getKeyAlgorithm() {
        return get(JweHeaderNames.ALGORITHM);
    }

    @Override
    public String getEncryptionAlgorithm() {
        return get(JweHeaderNames.ENCRYPTION_ALGORITHM);
    }

    public <T> T get(String name) {
        return (T) parameters.get(name);
    }
}
