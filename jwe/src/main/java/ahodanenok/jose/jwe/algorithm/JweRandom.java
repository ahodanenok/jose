package ahodanenok.jose.jwe.algorithm;

import java.security.SecureRandom;

public interface JweRandom {

    static JweRandom from(SecureRandom random) {
        return b -> random.nextBytes(b);
    }

    void randomBytes(byte[] bytes);
}
