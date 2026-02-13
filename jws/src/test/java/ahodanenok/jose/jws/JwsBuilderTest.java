package ahodanenok.jose.jws;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

import ahodanenok.jose.common.JsonConverter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class JwsBuilderTest {

    @Test
    public void testEmptyPayload() {
        Jws jws = Jws.builder()
            .withPayload(new byte[0])
            .withHeader()
                .protectedParams().param("alg", "none").set()
                .add()
            .withJsonConverter(new JacksonJsonConverter())
            .create();
        assertArrayEquals(new byte[0], jws.getPayload());
        // todo: check header & signature?
    }

    @Test
    public void testSomePayload() {
        Jws jws = Jws.builder()
            .withPayload(new byte[] { 1, 2, 3 })
            .withHeader()
                .protectedParams().param("alg", "none").set()
                .add()
            .withJsonConverter(new JacksonJsonConverter())
            .create();
        assertArrayEquals(new byte[] { 1, 2, 3 }, jws.getPayload());
        // todo: check header & signature?
    }

    @Test
    public void testProtectedHeaderWithCustomParams() {
        Jws jws = Jws.builder()
            .withHeader()
                .protectedParams()
                    .param("alg", "none")
                    .param("foo", 1)
                    .param("bar", true)
                    .set()
                .add()
            .withJsonConverter(new JacksonJsonConverter())
            .create();

        assertEquals("none", jws.getProtectedHeader().get("alg"));
        assertEquals(Integer.valueOf(1), jws.getProtectedHeader().get("foo"));
        assertEquals(true, jws.getProtectedHeader().get("bar"));
    }

    private static class JacksonJsonConverter implements JsonConverter {

        ObjectMapper mapper = new ObjectMapper();

        @Override
        public String convert(Object obj) {
            try {
                return mapper.writeValueAsString(obj);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
