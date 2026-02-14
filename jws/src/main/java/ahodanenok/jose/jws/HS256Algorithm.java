package ahodanenok.jose.jws;

import java.security.Key;
import java.util.Objects;

import javax.crypto.Mac;

public final class HS256Algorithm extends JwsAlgoritmBase {

    public static final String NAME = "HS256";

    private final Key secretKey;
    private final String provider;

    public HS256Algorithm(Key secretKey) {
        this(secretKey, null);
    }

    public HS256Algorithm(Key secretKey, String provider) {
        this.secretKey = Objects.requireNonNull(secretKey);
        this.provider = provider;
    }

    public String getName() {
        return NAME;
    }

    @Override
    public byte[] doSign(byte[] input) throws Exception {
        // todo: cache mac instance?
        Mac mac;
        if (provider != null) {
            mac = Mac.getInstance("HmacSHA256", provider);
        } else {
            mac = Mac.getInstance("HmacSHA256");
        }
        mac.init(secretKey);
        return mac.doFinal(input);
    }
}
