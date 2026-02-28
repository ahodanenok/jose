package ahodanenok.jose.jws;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ahodanenok.jose.common.Base64Url;
import ahodanenok.jose.common.JsonParser;

public final class JwsParser {

    public static JwsParserBuilder builder() {
        return new JwsParserBuilder();
    }

    private final JwsSerialization serialization;
    private final List<JwsAlgorithm> algorithms;
    private final JsonParser jsonParser;

    JwsParser(
            JwsSerialization serialization,
            List<JwsAlgorithm> algorithms,
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

        return new JwsInputOneSignature(jws, valid);
    }

    private JwsInput parseJsonFlat(String str) {
        Map<String, Object> obj;
        try {
            obj = jsonParser.parse(str);
        } catch (Exception e) {
            throw new JwsException("Failed to parse JWS", e);
        }

        // todo: validate properties' values are strings
        String protectedHeaderEncoded = (String) obj.get("protected");
        JwsHeader protectedHeader = parseProtectedHeader(protectedHeaderEncoded);
        String payloadEncoded = (String) obj.get("payload");
        byte[] signature = Base64Url.decode((String) obj.get("signature"));

        Jws jws = new JwsOneSignature(
            Base64Url.decode(payloadEncoded, false), protectedHeader, signature, str);
        boolean valid = verifySignature(
            payloadEncoded, protectedHeaderEncoded, protectedHeader, signature);

        return new JwsInputOneSignature(jws, valid);
    }

    private JwsInput parseJson(String str) {
        Map<String, Object> obj;
        try {
            obj = jsonParser.parse(str);
        } catch (Exception e) {
            throw new JwsException("Failed to parse JWS", e);
        }

        String payloadEncoded = (String) obj.get("payload");

        // todo: validate properties' values
        List<Map<String, Object>> signaturesArray = (List<Map<String, Object>>) obj.get("signatures");
        // todo: check not empty
        if (signaturesArray.size() == 1) {
            Map<String, Object> signatureObj = (Map<String, Object>) signaturesArray.get(0);

            String protectedHeaderEncoded = (String) signatureObj.get("protected");
            JwsHeader protectedHeader = parseProtectedHeader(protectedHeaderEncoded);
            byte[] signature = Base64Url.decode((String) signatureObj.get("signature"));

            Jws jws = new JwsOneSignature(
                Base64Url.decode(payloadEncoded, false), protectedHeader, signature, str);
            boolean valid = verifySignature(
                payloadEncoded, protectedHeaderEncoded, protectedHeader, signature);

            return new JwsInputOneSignature(jws, valid);
        } else {
            List<JwsHeader> protectedHeaders = new ArrayList<>(signaturesArray.size());
            List<byte[]> signatures = new ArrayList<>(signaturesArray.size());
            List<Integer> invalidSignatures = null;
            for (int i = 0; i < signaturesArray.size(); i++) {
                Map<String, Object> signatureObj = (Map<String, Object>) signaturesArray.get(i);

                String protectedHeaderEncoded = (String) signatureObj.get("protected");
                JwsHeader protectedHeader = parseProtectedHeader(protectedHeaderEncoded);
                byte[] signature = Base64Url.decode((String) signatureObj.get("signature"));

                if (!verifySignature(payloadEncoded, protectedHeaderEncoded, protectedHeader, signature)) {
                    if (invalidSignatures == null) {
                        invalidSignatures = new ArrayList<>();
                    }

                    invalidSignatures.add(i);
                }

                protectedHeaders.add(protectedHeader);
                signatures.add(signature);
            }

            Jws jws = new JwsMultipleSignatures(
                Base64Url.decode(payloadEncoded, false), protectedHeaders, signatures, str);
            if (invalidSignatures == null) {
                invalidSignatures = List.of();
            }

            return new JwsInputMultipleSignatures(jws, invalidSignatures);
        }
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

        JwsAlgorithm algorithmUsed = null;
        for (JwsAlgorithm algorithm : algorithms) {
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
