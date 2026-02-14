package ahodanenok.jose.jws;

import java.util.LinkedHashMap;
import java.util.Objects;

public final class JwsHeaderDescription {

    private final JwsBuilder jwsBuilder;
    private JwsHeader protectedHeader;

    JwsHeaderDescription(JwsBuilder jwsBuilder) {
        this.jwsBuilder = Objects.requireNonNull(jwsBuilder);
    }

    public ProtectedParams protectedParams() {
        return new ProtectedParams();
    }

    public JwsBuilder add() {
        // todo: invalidate to prevent reuse?
        // todo: use a null object for missing headers
        jwsBuilder.protectedHeaders.add(protectedHeader);
        return jwsBuilder;
    }

    public final class ProtectedParams {

        // Use LinkedHashMap to allow the generation of json with the same order of params
        private final LinkedHashMap<String, Object> params = new LinkedHashMap<>();

        public ProtectedParams param(String name, Object value) {
            // todo: value nullable?
            params.put(Objects.requireNonNull(name), value);
            return this;
        }

        public JwsHeaderDescription set() {
            // todo: invalidate to prevent reuse?
            JwsHeaderDescription.this.protectedHeader = new JwsHeader(params);
            return JwsHeaderDescription.this;
        }
    }
}
