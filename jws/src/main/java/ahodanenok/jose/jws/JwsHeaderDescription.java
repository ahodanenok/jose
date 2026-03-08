package ahodanenok.jose.jws;

import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.function.Consumer;

public final class JwsHeaderDescription {

    private final JwsBuilder jwsBuilder;
    private JwsHeader protectedHeader;
    private JwsHeader unprotectedHeader;

    JwsHeaderDescription(JwsBuilder jwsBuilder) {
        this.jwsBuilder = Objects.requireNonNull(jwsBuilder);
    }

    public Params protectedParams() {
        return new Params(params ->
            JwsHeaderDescription.this.protectedHeader = params);
    }

    public Params unprotectedParams() {
        return new Params(params ->
            JwsHeaderDescription.this.unprotectedHeader = params);
    }

    public JwsBuilder add() {
        // todo: invalidate to prevent reuse?
        // todo: use a null object for missing headers
        jwsBuilder.joseParams.add(new JwsBuilder.JoseParams(
            protectedHeader, unprotectedHeader));
        return jwsBuilder;
    }

    public final class Params {

        // Use LinkedHashMap to allow the generation of json with the same order of params
        private final LinkedHashMap<String, Object> params = new LinkedHashMap<>();
        private final Consumer<JwsHeader> paramsConsumer;

        Params(Consumer<JwsHeader> paramsConsumer) {
            this.paramsConsumer = paramsConsumer;
        }

        public Params param(String name, Object value) {
            // todo: value nullable?
            params.put(Objects.requireNonNull(name), value);
            return this;
        }

        public JwsHeaderDescription set() {
            // todo: invalidate to prevent reuse?
            paramsConsumer.accept(new JwsHeader(params));
            return JwsHeaderDescription.this;
        }
    }
}
