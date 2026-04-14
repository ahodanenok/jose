package ahodanenok.jose.jwe;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import ahodanenok.jose.common.JsonConverter;
import ahodanenok.jose.jwe.algorithm.JweEncryptionAlgorithm;
import ahodanenok.jose.jwe.algorithm.JweKeyAlgorithm;

public final class JweBuilder {

    private byte[] payload;
    private JweHeader protectedHeader;
    private JweHeader unprotectedHeader;
    private JweSerialization serialization;
    private JsonConverter jsonConverter;
    private List<JweKeyAlgorithm> keyAlgorithms = new ArrayList<>();
    private List<JweEncryptionAlgorithm> encryptionAlgorithms = new ArrayList<>();

    public JweBuilder withPayload(byte[] payload) {
        this.payload = Objects.requireNonNull(payload);
        return this;
    }

    public JweHeaderParams withProtectedHeader() {
        return new JweHeaderParams(header -> protectedHeader = header);
    }

    public JweHeaderParams withUnprotectedHeader() {
        return new JweHeaderParams(header -> unprotectedHeader = header);
    }

    public JweBuilder serializedAs(JweSerialization serialization) {
        this.serialization = Objects.requireNonNull(serialization);
        return this;
    }

    public JweBuilder useJsonConverter(JsonConverter jsonConverter) {
        this.jsonConverter = Objects.requireNonNull(jsonConverter);
        return this;
    }

    public JweBuilder alloweKeyAlgorithm(JweKeyAlgorithm algorithm) {
        keyAlgorithms.add(algorithm);
        return this;
    }

    public JweBuilder alloweEncryptionAlgorithm(JweEncryptionAlgorithm algorithm) {
        encryptionAlgorithms.add(algorithm);
        return this;
    }

    public Jwe create() {
        return null;
    }

    public final class JweHeaderParams {

        // Use LinkedHashMap to allow generation of json with the same order of params
        private final LinkedHashMap<String, Object> params;
        private final Consumer<JweHeader> paramsConsumer;

        JweHeaderParams(Consumer<JweHeader> paramsConsumer) {
            this.params = new LinkedHashMap<>();
            this.paramsConsumer = paramsConsumer;
        }

        public JweHeaderParams param(String name, Object value) {
            // todo: value nullable?
            params.put(Objects.requireNonNull(name), value);
            return this;
        }

        public JweBuilder set() {
            // todo: invalidate to prevent reuse?
            paramsConsumer.accept(new JweHeader(params));
            return JweBuilder.this;
        }
    }
}
