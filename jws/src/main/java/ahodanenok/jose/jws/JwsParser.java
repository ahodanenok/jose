package ahodanenok.jose.jws;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import ahodanenok.jose.common.Base64Url;
import ahodanenok.jose.common.JsonParser;

public final class JwsParser {

    public static JwsParserBuilder builder() {
        return new JwsParserBuilder();
    }

    private final JwsSerialization serialization;
    private final List<JwsAlgoritm> algorithms;
    private final JsonParser jsonParser;

    JwsParser(
            JwsSerialization serialization,
            List<JwsAlgoritm> algorithms,
            JsonParser jsonParser) {
        this.serialization = serialization;
        this.algorithms = algorithms;
        this.jsonParser = jsonParser;
    }

    public JwsInput parse(String str) {
        return switch(serialization) {
            case COMPACT -> parseCompact(str);
            case JSON_FLAT -> parseJsonFlat(str);
            case JSON -> parseJson(str);
        };
    }

    private JwsInput parseCompact(String str) {
        // todo: static regex
        String[] parts = str.split("\\.");
        if (parts.length != 3) {
            throw new JwsException("Illegal compact representation of a JWS");
        }

        // todo: handle json not valid?
        // todo: no duplicate header params
        String protectedHeaderEncoded = parts[0];
        JwsHeader protectedHeader = new JwsHeader(jsonParser.parse(new String(
            Base64Url.decode(protectedHeaderEncoded, false), StandardCharsets.UTF_8)));
        // todo: verify crit parameter
        String payloadEncoded = parts[1];
        byte[] signature = Base64Url.decode(parts[2], false);

        Jws jws = new JwsOneSignature(
            Base64Url.decode(payloadEncoded, false), protectedHeader, signature, str);
        boolean valid = verifySignature(
            payloadEncoded, protectedHeaderEncoded, protectedHeader, signature);

        return new JwsInput(jws, valid);
    }

    private JwsInput parseJsonFlat(String str) {


        return null;
    }

    private JwsInput parseJson(String str) {
        return null;
    }

    private boolean verifySignature(
            String payloadEncoded,
            String protectedHeaderEncoded,
            JwsHeader protectedHeader,
            byte[] signature) {
        String algorithmName = protectedHeader.get("alg");
        // todo: check present

        JwsAlgoritm algorithmUsed = null;
        for (JwsAlgoritm algorithm : algorithms) {
            if (algorithm.getName().equals(algorithmName)) {
                algorithmUsed = algorithm;
            }
        }
        if (algorithmUsed == null) {
            return false;
        }

        byte[] signatureComputed = algorithmUsed.sign(
            (protectedHeaderEncoded + "." + payloadEncoded)
                .getBytes(StandardCharsets.US_ASCII));

        return Arrays.equals(signature, signatureComputed);
    }
}
