package ahodanenok.jose.jws;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class JwsAlgorithmTest {

    @Test
    public void testNone() {
        assertArrayEquals(new byte[0], new NoneAlgoritm().sign(""));
        assertArrayEquals(new byte[0], new NoneAlgoritm().sign("abc"));
        assertArrayEquals(new byte[0], new NoneAlgoritm().sign("UzI1NiJ9.0dHA6Ly9leGFt"));
    }
}
