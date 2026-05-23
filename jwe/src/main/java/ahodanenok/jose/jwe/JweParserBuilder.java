package ahodanenok.jose.jwe;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ahodanenok.jose.common.JsonParser;
import ahodanenok.jose.jwe.algorithm.JweKeyAlgorithm;
import ahodanenok.jose.jwe.algorithm.JweEncryptionAlgorithm;

public final class JweParserBuilder {

    private JweSerialization serialization;
    private List<JweKeyAlgorithm> allowedKeyAlgorithms;
    private List<JweEncryptionAlgorithm> allowedEncryptionAlgorithms;
    private JsonParser jsonParser;

    JweParserBuilder() {
        serialization = JweSerialization.COMPACT;
        allowedKeyAlgorithms = new ArrayList<>();
        allowedEncryptionAlgorithms = new ArrayList<>();
    }

    public JweParserBuilder forSerialization(JweSerialization serialization) {
        this.serialization = Objects.requireNonNull(serialization);
        return this;
    }

    public JweParserBuilder alloweKeyAlgorithm(JweKeyAlgorithm algorithm) {
        allowedKeyAlgorithms.add(Objects.requireNonNull(algorithm));
        return this;
    }

    public JweParserBuilder allowedEncryptionAlgorithm(JweEncryptionAlgorithm algorithm) {
        allowedEncryptionAlgorithms.add(Objects.requireNonNull(algorithm));
        return this;
    }

    public JweParserBuilder withJsonParser(JsonParser jsonParser) {
        this.jsonParser = Objects.requireNonNull(jsonParser);
        return this;
    }

    public JweParser build() {
        if (allowedKeyAlgorithms.isEmpty()) {
            throw new IllegalStateException("Allow at least one key algorithm");
        }

        if (allowedEncryptionAlgorithms.isEmpty()) {
            throw new IllegalStateException("Allow at least one encryption algorithm");
        }

        if (jsonParser == null) {
            throw new IllegalStateException("Json parser is not provided");
        }

        return new JweParser(
            serialization,
            allowedKeyAlgorithms,
            allowedEncryptionAlgorithms,
            jsonParser);
    }
}
