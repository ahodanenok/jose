package ahodanenok.jose.jws;

import java.util.HashMap;
import java.util.Objects;
import java.util.Map;

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

        private final Map<String, Object> params = new HashMap<>();

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
