package ahodanenok.jose.jws;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class JwsAlgorithmTest {

    @Test
    public void testNone() {
        assertArrayEquals(new byte[0], new NoneAlgoritm().sign(new byte[0]));
        assertArrayEquals(new byte[0], new NoneAlgoritm().sign("abc".getBytes(StandardCharsets.US_ASCII)));
        assertArrayEquals(new byte[0], new NoneAlgoritm().sign("UzI1NiJ9.0dHA6Ly9leGFt".getBytes(StandardCharsets.US_ASCII)));
    }
}
