package ahodanenok.jose.jwe;

import java.util.Map;

public final class JweHeader {

    final Map<String, Object> parameters;

    JweHeader(Map<String, Object> parameters) {
        this.parameters = parameters;
    }

    public <T> T get(String name) {
        return (T) parameters.get(name);
    }
}
