package ahodanenok.jose.jws;

import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

import ahodanenok.jose.common.Base64Url;
import ahodanenok.jose.common.JsonConverter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class JwsBuilderTest {

    @Test
    public void testEmptyPayload() throws Exception {
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Jws jws = Jws.builder()
            .withPayload(new byte[0])
            .withHeader()
                .protectedParams().param("alg", "HS256").set()
                .add()
            .allowAlgorithm(new HS256Algorithm(key))
            .useJsonConverter(new JacksonJsonConverter())
            .serializedAs(JwsSerialization.COMPACT)
            .create();

        assertArrayEquals(new byte[0], jws.getPayload());
        assertEquals("HS256", jws.getProtectedHeader().get("alg"));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] signature = mac.doFinal("eyJhbGciOiJIUzI1NiJ9.".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(signature, jws.getSignature());
        assertEquals("eyJhbGciOiJIUzI1NiJ9.." + Base64Url.encode(signature, false), jws.asString());
    }

    @Test
    public void testSomePayload() throws Exception {
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Jws jws = Jws.builder()
            .withPayload(new byte[] { 1, 2, 3 })
            .withHeader()
                .protectedParams().param("alg", "HS256").set()
                .add()
            .allowAlgorithm(new HS256Algorithm(key))
            .useJsonConverter(new JacksonJsonConverter())
            .serializedAs(JwsSerialization.COMPACT)
            .create();

        assertArrayEquals(new byte[] { 1, 2, 3 }, jws.getPayload());
        assertEquals("HS256", jws.getProtectedHeader().get("alg"));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] signature = mac.doFinal("eyJhbGciOiJIUzI1NiJ9.AQID".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(signature, jws.getSignature());
        assertEquals("eyJhbGciOiJIUzI1NiJ9.AQID." + Base64Url.encode(signature, false), jws.asString());
    }

    @Test
    public void testProtectedHeaderWithCustomParams() throws Exception {
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        byte[] payload = "Hello, world!".getBytes(StandardCharsets.US_ASCII);
        Jws jws = Jws.builder()
            .withPayload(payload)
            .withHeader()
                .protectedParams()
                    .param("alg", "HS256")
                    .param("foo", 1)
                    .param("bar", true)
                    .set()
                .add()
            .allowAlgorithm(new HS256Algorithm(key))
            .useJsonConverter(new JacksonJsonConverter())
            .serializedAs(JwsSerialization.COMPACT)
            .create();

        assertArrayEquals(payload, jws.getPayload());
        assertEquals("HS256", jws.getProtectedHeader().get("alg"));
        assertEquals(Integer.valueOf(1), jws.getProtectedHeader().get("foo"));
        assertEquals(true, jws.getProtectedHeader().get("bar"));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] signature = mac.doFinal("eyJhbGciOiJIUzI1NiIsImZvbyI6MSwiYmFyIjp0cnVlfQ.SGVsbG8sIHdvcmxkIQ".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(signature, jws.getSignature());
        assertEquals("eyJhbGciOiJIUzI1NiIsImZvbyI6MSwiYmFyIjp0cnVlfQ.SGVsbG8sIHdvcmxkIQ." + Base64Url.encode(signature, false), jws.asString());
    }

    @Test
    public void testJsonFlatSerializationWithoutUnprotectedHeader() throws Exception {
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Jws jws = Jws.builder()
            .withPayload(new byte[] { 1, 2, 3 })
            .withHeader()
                .protectedParams().param("alg", "HS256").set()
                .add()
            .allowAlgorithm(new HS256Algorithm(key))
            .useJsonConverter(new JacksonJsonConverter())
            .serializedAs(JwsSerialization.JSON_FLAT)
            .create();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] signature = mac.doFinal("eyJhbGciOiJIUzI1NiJ9.AQID".getBytes(StandardCharsets.US_ASCII));
        assertEquals(
            "{\"payload\":\"AQID\",\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"" + Base64Url.encode(signature, false) + "\"}",
            jws.asString());
        System.out.println("!!! " + jws.asString());
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
