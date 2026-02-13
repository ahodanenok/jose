package ahodanenok.jose.jws;

import java.util.Objects;
import java.util.Map;

import ahodanenok.jose.common.JsonConverter;

public final class JwsHeader {

    static final JwsHeader EMPTY = new JwsHeader(Map.of());

    private final Map<String, Object> parameters;

    JwsHeader(Map<String, Object> parameters) {
        this.parameters = Objects.requireNonNull(parameters);
    }

    public <T> T get(String name) {
        return (T) parameters.get(name);
    }

    public String getAlgorithm() {
        // todo: constants for standard header parameters
        return (String) parameters.get("alg");
    }

    public String asJson(JsonConverter converter) {
        return converter.convert(parameters);
    }
}
