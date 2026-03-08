package ahodanenok.jose.jws;

import java.nio.charset.StandardCharsets;
import java.security.Key;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

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
            .useJsonConverter(new JacksonJson())
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
            .useJsonConverter(new JacksonJson())
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
            .useJsonConverter(new JacksonJson())
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
            .useJsonConverter(new JacksonJson())
            .serializedAs(JwsSerialization.JSON_FLAT)
            .create();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] signature = mac.doFinal("eyJhbGciOiJIUzI1NiJ9.AQID".getBytes(StandardCharsets.US_ASCII));
        assertEquals(
            "{\"payload\":\"AQID\",\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"" + Base64Url.encode(signature, false) + "\"}",
            jws.asString());
    }

    @Test
    public void testJsonFlatSerializationWithUnprotectedHeader() throws Exception {
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Jws jws = Jws.builder()
            .withPayload(new byte[] { 1, 2, 3 })
            .withHeader()
                .protectedParams().param("alg", "HS256").set()
                .unprotectedParams().param("typ", "JWS").set()
                .add()
            .allowAlgorithm(new HS256Algorithm(key))
            .useJsonConverter(new JacksonJson())
            .serializedAs(JwsSerialization.JSON_FLAT)
            .create();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] signature = mac.doFinal("eyJhbGciOiJIUzI1NiJ9.AQID".getBytes(StandardCharsets.US_ASCII));
        assertEquals(
            "{\"payload\":\"AQID\",\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"header\":{\"typ\":\"JWS\"},\"signature\":\"" + Base64Url.encode(signature, false) + "\"}",
            jws.asString());
    }

    @Test
    public void testJsonSerializationOneSignature() throws Exception {
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Jws jws = Jws.builder()
            .withPayload(new byte[] { 1, 2, 3 })
            .withHeader()
                .protectedParams().param("alg", "HS256").set()
                .add()
            .allowAlgorithm(new HS256Algorithm(key))
            .useJsonConverter(new JacksonJson())
            .serializedAs(JwsSerialization.JSON)
            .create();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] signature = mac.doFinal("eyJhbGciOiJIUzI1NiJ9.AQID".getBytes(StandardCharsets.US_ASCII));
        assertEquals(
            "{\"payload\":\"AQID\",\"signatures\":[{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"" + Base64Url.encode(signature, false) + "\"}]}",
            jws.asString());
    }

    @Test
    public void testJsonSerializationOneSignatureWithUnprotectedHeader() throws Exception {
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Jws jws = Jws.builder()
            .withPayload(new byte[] { 1, 2, 3 })
            .withHeader()
                .protectedParams().param("alg", "HS256").set()
                .unprotectedParams().param("typ", "JWS").set()
                .add()
            .allowAlgorithm(new HS256Algorithm(key))
            .useJsonConverter(new JacksonJson())
            .serializedAs(JwsSerialization.JSON)
            .create();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] signature = mac.doFinal("eyJhbGciOiJIUzI1NiJ9.AQID".getBytes(StandardCharsets.US_ASCII));
        assertEquals(
            "{\"payload\":\"AQID\",\"signatures\":[{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"header\":{\"typ\":\"JWS\"},\"signature\":\"" + Base64Url.encode(signature, false) + "\"}]}",
            jws.asString());
    }

    @Test
    public void testJsonSerializationMultipleSignatures() throws Exception {
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Jws jws = Jws.builder()
            .withPayload(new byte[] { 1, 2, 3 })
            .withHeader()
                .protectedParams().param("alg", "HS256").set()
                .add()
            .withHeader()
                .protectedParams().param("alg", "none").set()
                .add()
            .allowAlgorithm(new HS256Algorithm(key))
            .allowAlgorithm(NoneAlgorithm.INSTANCE)
            .useJsonConverter(new JacksonJson())
            .serializedAs(JwsSerialization.JSON)
            .create();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] signature = mac.doFinal("eyJhbGciOiJIUzI1NiJ9.AQID".getBytes(StandardCharsets.US_ASCII));
        assertEquals(
            "{\"payload\":\"AQID\",\"signatures\":[{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"signature\":\"" + Base64Url.encode(signature, false) + "\"},{\"protected\":\"eyJhbGciOiJub25lIn0\",\"signature\":\"\"}]}",
            jws.asString());
    }

    @Test
    public void testJsonSerializationMultipleSignaturesWithUnprotectedHeader() throws Exception {
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Jws jws = Jws.builder()
            .withPayload(new byte[] { 1, 2, 3 })
            .withHeader()
                .protectedParams().param("alg", "HS256").set()
                .unprotectedParams().param("x", 1).set()
                .add()
            .withHeader()
                .protectedParams().param("alg", "none").set()
                .unprotectedParams().param("y", 2).set()
                .add()
            .allowAlgorithm(new HS256Algorithm(key))
            .allowAlgorithm(NoneAlgorithm.INSTANCE)
            .useJsonConverter(new JacksonJson())
            .serializedAs(JwsSerialization.JSON)
            .create();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] signature = mac.doFinal("eyJhbGciOiJIUzI1NiJ9.AQID".getBytes(StandardCharsets.US_ASCII));
        assertEquals(
            "{\"payload\":\"AQID\",\"signatures\":[{\"protected\":\"eyJhbGciOiJIUzI1NiJ9\",\"header\":{\"x\":1},\"signature\":\"" + Base64Url.encode(signature, false) + "\"},{\"protected\":\"eyJhbGciOiJub25lIn0\",\"header\":{\"y\":2},\"signature\":\"\"}]}",
            jws.asString());
    }
}
