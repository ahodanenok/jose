package ahodanenok.jose.jws;

import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class JwsAlgorithmTest {

    @Test
    public void testNone() {
        NoneAlgoritm alg = new NoneAlgoritm();
        assertArrayEquals(new byte[0], alg.sign(new byte[0]));
        assertArrayEquals(new byte[0], alg.sign("abc".getBytes(StandardCharsets.US_ASCII)));
        assertArrayEquals(new byte[0], alg.sign("UzI1NiJ9.0dHA6Ly9leGFt".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    public void testHS256() throws Exception {
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        HS256Algorithm alg = new HS256Algorithm(key);

        assertArrayEquals(mac.doFinal(new byte[0]), alg.sign(new byte[0]));
        assertArrayEquals(mac.doFinal(new byte[] { 1, 2, 3}), alg.sign(new byte[] { 1, 2, 3 }));
    }
}
