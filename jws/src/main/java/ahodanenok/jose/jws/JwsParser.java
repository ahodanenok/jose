package ahodanenok.jose.jws;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

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
        JwsHeader protectedHeader = parseProtectedHeader(protectedHeaderEncoded);
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
        Map<String, Object> obj;
        try {
            obj = jsonParser.parse(str);
        } catch (Exception e) {
            throw new JwsException("Failed to parse JWS", e);
        }

        String protectedHeaderEncoded = (String) obj.get("protected");
        JwsHeader protectedHeader = parseProtectedHeader(protectedHeaderEncoded);
        String payloadEncoded = (String) obj.get("payload");
        byte[] signature = Base64Url.decode((String) obj.get("signature"));

        Jws jws = new JwsOneSignature(
            Base64Url.decode(payloadEncoded, false), protectedHeader, signature, str);
        boolean valid = verifySignature(
            payloadEncoded, protectedHeaderEncoded, protectedHeader, signature);

        return new JwsInput(jws, valid);
    }

    private JwsInput parseJson(String str) {
        return null;
    }

    private JwsHeader parseProtectedHeader(String protectedHeaderEncoded) {
        String json = new String(
            Base64Url.decode(protectedHeaderEncoded, false),
            StandardCharsets.UTF_8);

        Map<String, Object> params;
        try {
            params = jsonParser.parse(json);
        } catch (Exception e) {
            throw new JwsException("Failed to parse protected header", e);
        }

        return new JwsHeader(params);
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

        return algorithmUsed.verify(
            (protectedHeaderEncoded + "." + payloadEncoded).getBytes(StandardCharsets.US_ASCII),
            signature);
    }
}
