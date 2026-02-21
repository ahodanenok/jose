package ahodanenok.jose.jws;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ahodanenok.jose.common.JsonParser;

public final class JwsParserBuilder {

    private JwsSerialization serialization;
    private final List<JwsAlgoritm> algorithms;
    private JsonParser jsonParser;

    JwsParserBuilder() {
        serialization = JwsSerialization.COMPACT;
        algorithms = new ArrayList<>();
        // todo: search for a json parser automatically?
    }

    public JwsParserBuilder forSerialization(JwsSerialization serialization) {
        this.serialization = Objects.requireNonNull(serialization);
        return this;
    }

    public JwsParserBuilder allowAlgorithm(JwsAlgoritm algorithm) {
        algorithms.add(Objects.requireNonNull(algorithm));
        return this;
    }

    public JwsParserBuilder withJsonParser(JsonParser jsonParser) {
        this.jsonParser = jsonParser;
        return this;
    }

    public JwsParser create() {
        if (algorithms.isEmpty()) {
            throw new IllegalStateException("Allow at least one algorithm");
        }

        if (jsonParser == null) {
            throw new IllegalStateException("Json parser is not provided");
        }

        return new JwsParser(serialization, algorithms, jsonParser);
    }
}
