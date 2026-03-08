package ahodanenok.jose.jws;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ahodanenok.jose.common.JsonConverter;

public final class JwsHeader implements JwsJoseHeader {

    static final JwsHeader EMPTY = new JwsHeader(Map.of());

    final Map<String, Object> parameters;

    JwsHeader(Map<String, Object> parameters) {
        this.parameters = Objects.requireNonNull(parameters);
    }

    public Set<String> parameterNames() {
        return Collections.unmodifiableSet(parameters.keySet());
    }

    @Override
    public <T> T get(String name) {
        return (T) parameters.get(name);
    }

    @Override
    public String getAlgorithm() {
        // todo: constants for standard header parameters
        return (String) parameters.get("alg");
    }
}
