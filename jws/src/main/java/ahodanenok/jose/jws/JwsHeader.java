package ahodanenok.jose.jws;

import java.util.Objects;
import java.util.Map;

public final class JwsHeader {

    private final Map<String, Object> parameters;

    JwsHeader(Map<String, Object> parameters) {
        this.parameters = Objects.requireNonNull(parameters);
    }

    public <T> T get(String name) {
        return (T) parameters.get(name);
    }
}
