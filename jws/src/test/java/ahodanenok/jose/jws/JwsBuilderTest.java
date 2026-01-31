package ahodanenok.jose.jws;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class JwsBuilderTest {

    @Test
    public void testEmpty() {
        Jws jws = Jws.builder().create();
        assertArrayEquals(new byte[0], jws.getPayload());
        // todo: check header & signature?
    }

    @Test
    public void testEmptyPayload() {
        Jws jws = Jws.builder()
            .withPayload(new byte[0])
            .create();
        assertArrayEquals(new byte[0], jws.getPayload());
        // todo: check header & signature?
    }

    @Test
    public void testSomePayload() {
        Jws jws = Jws.builder()
            .withPayload(new byte[] { 1, 2, 3 })
            .create();
        assertArrayEquals(new byte[] { 1, 2, 3 }, jws.getPayload());
        // todo: check header & signature?
    }

    @Test
    public void testProtectedHeaderWithCustomParams() {
        Jws jws = Jws.builder()
            .withHeader()
                .protectedParams()
                    .param("foo", 1)
                    .param("bar", true)
                    .set()
                .add()
            .create();

        assertEquals(Integer.valueOf(1), jws.getProtectedHeader().get("foo"));
        assertEquals(true, jws.getProtectedHeader().get("bar"));
    }
}
