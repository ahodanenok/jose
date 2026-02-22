package ahodanenok.jose.jws;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import ahodanenok.jose.common.Base64Url;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JwsParserTest {

    @Test
    public void testParseCompactValid() {
        JwsParser parser = JwsParser.builder()
            .forSerialization(JwsSerialization.COMPACT)
            .allowAlgorithm(new HS256Algorithm(new SecretKeySpec(Base64Url.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"), "HmacSHA256")))
            .withJsonParser(new JacksonJson())
            .create();

        // https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
        String str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        JwsInput input = parser.parse(str);
        assertTrue(input.isValid());
        Jws jws = input.accept();
        assertEquals("JWT", jws.getProtectedHeader().get("typ"));
        assertEquals("HS256", jws.getProtectedHeader().get("alg"));
        assertArrayEquals(
            TestUtils.bytes(123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125),
            jws.getPayload());
        assertArrayEquals(
            TestUtils.bytes(116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121),
            jws.getSignature());
        assertEquals(str, jws.asString());
    }

    @Test
    public void testParseCompactNotValid() {
        JwsParser parser = JwsParser.builder()
            .forSerialization(JwsSerialization.COMPACT)
            .allowAlgorithm(new HS256Algorithm(new SecretKeySpec(Base64Url.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"), "HmacSHA256")))
            .withJsonParser(new JacksonJson())
            .create();

        // https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
        // payload modified - starts with uppercase 'E' instead of 'e'
        String str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.EyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        JwsInput input = parser.parse(str);
        assertFalse(input.isValid());
        Jws jws = input.accept();
        assertEquals("JWT", jws.getProtectedHeader().get("typ"));
        assertEquals("HS256", jws.getProtectedHeader().get("alg"));
        assertArrayEquals(
            TestUtils.bytes(19, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125),
            jws.getPayload());
        assertArrayEquals(
            TestUtils.bytes(116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121),
            jws.getSignature());
        assertEquals(str, jws.asString());
    }

    @Test
    public void testParseJsonFlattenedValid() {
        JwsParser parser = JwsParser.builder()
            .forSerialization(JwsSerialization.JSON_FLAT)
            .allowAlgorithm(new HS256Algorithm(new SecretKeySpec(Base64Url.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"), "HmacSHA256")))
            .withJsonParser(new JacksonJson())
            .create();

        // https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
        String str =
        """
        {
            "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
            "signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        }
        """;
        JwsInput input = parser.parse(str);
        assertTrue(input.isValid());
        Jws jws = input.accept();
        assertEquals("JWT", jws.getProtectedHeader().get("typ"));
        assertEquals("HS256", jws.getProtectedHeader().get("alg"));
        assertArrayEquals(
            TestUtils.bytes(123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125),
            jws.getPayload());
        assertArrayEquals(
            TestUtils.bytes(116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121),
            jws.getSignature());
        assertEquals(str, jws.asString());
    }

    @Test
    public void testParseJsonFlattenedNotValid() {
        JwsParser parser = JwsParser.builder()
            .forSerialization(JwsSerialization.JSON_FLAT)
            .allowAlgorithm(new HS256Algorithm(new SecretKeySpec(Base64Url.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"), "HmacSHA256")))
            .withJsonParser(new JacksonJson())
            .create();

        // https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.1
        // payload modified - starts with uppercase 'E' instead of 'e'
        String str =
        """
        {
            "payload": "EyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "protected": "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
            "signature": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        }
        """;
        JwsInput input = parser.parse(str);
        assertFalse(input.isValid());
        Jws jws = input.accept();
        assertEquals("JWT", jws.getProtectedHeader().get("typ"));
        assertEquals("HS256", jws.getProtectedHeader().get("alg"));
        assertArrayEquals(
            TestUtils.bytes(19, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125),
            jws.getPayload());
        assertArrayEquals(
            TestUtils.bytes(116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121),
            jws.getSignature());
        assertEquals(str, jws.asString());
    }
}
