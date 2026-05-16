package ahodanenok.jose.jwe;

import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import ahodanenok.jose.jwe.algorithm.A128GcmEncryptionAlgorithm;
import ahodanenok.jose.jwe.algorithm.DirectKeyAlgorithm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class JweBuilderTest {

    @Test
    public void testCompact_DirectEncryption() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new byte[] { 1 });

        Jwe jwe = Jwe.builder()
            .withPayload(TestUtils.bytes(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21))
            .withProtectedHeader()
                .param(JweHeaderNames.ALGORITHM, "dir")
                .param(JweHeaderNames.ENCRYPTION_ALGORITHM, "A128GCM")
                .set()
            .withAdditionalAuthenticatedData(TestUtils.bytes(0xAB))
            .allowedKeyAlgorithm(new DirectKeyAlgorithm(new SecretKeySpec(
                TestUtils.bytes(0x39, 0x3c, 0xa1, 0x5b, 0xec, 0x54, 0x1e, 0xff, 0x8c, 0xde, 0x67, 0xb9, 0x66, 0x9c, 0x2f, 0x3c), "AES")))
            .allowedEncryptionAlgorithm(new A128GcmEncryptionAlgorithm().useRandom(random))
            .serializedAs(JweSerialization.COMPACT)
            .useJsonConverter(new JacksonJson())
            .create();

        assertArrayEquals(TestUtils.bytes(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21), jwe.getPayload());
        assertEquals("dir", jwe.getProtectedHeader().get(JweHeaderNames.ALGORITHM));
        assertEquals("A128GCM", jwe.getProtectedHeader().get(JweHeaderNames.ENCRYPTION_ALGORITHM));
        assertEquals(null, jwe.getUnprotectedHeader());
        assertEquals("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..CisqglFlrpdCxjsM.ooTLw6K49EyaFphpVg.RBIIDzevKfm7u39a7DjlTg", jwe.asString());
    }

    @Test
    public void testJsonFlat_DirectEncryption() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new byte[] { 1 });

        Jwe jwe = Jwe.builder()
            .withPayload(TestUtils.bytes(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21))
            .withProtectedHeader()
                .param(JweHeaderNames.ALGORITHM, "dir")
                .param(JweHeaderNames.ENCRYPTION_ALGORITHM, "A128GCM")
                .set()
            .withUnprotectedHeader()
                .param("foo", "bar")
                .set()
            .withAdditionalAuthenticatedData(TestUtils.bytes(0xAB))
            .allowedKeyAlgorithm(new DirectKeyAlgorithm(new SecretKeySpec(
                TestUtils.bytes(0x39, 0x3c, 0xa1, 0x5b, 0xec, 0x54, 0x1e, 0xff, 0x8c, 0xde, 0x67, 0xb9, 0x66, 0x9c, 0x2f, 0x3c), "AES")))
            .allowedEncryptionAlgorithm(new A128GcmEncryptionAlgorithm().useRandom(random))
            .serializedAs(JweSerialization.JSON_FLAT)
            .useJsonConverter(new JacksonJson())
            .create();

        assertArrayEquals(TestUtils.bytes(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21), jwe.getPayload());
        assertEquals("dir", jwe.getProtectedHeader().get(JweHeaderNames.ALGORITHM));
        assertEquals("A128GCM", jwe.getProtectedHeader().get(JweHeaderNames.ENCRYPTION_ALGORITHM));
        assertEquals("bar", jwe.getUnprotectedHeader().get("foo"));
        assertEquals("{\"protected\":\"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0\",\"unprotected\":{\"foo\":\"bar\"},\"aad\":\"qw\",\"iv\":\"CisqglFlrpdCxjsM\",\"ciphertext\":\"ooTLw6K49EyaFphpVg\",\"tag\":\"RBIIDzevKfm7u39a7DjlTg\"}", jwe.asString());
    }

    @Test
    public void testJson_DirectEncryption() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new byte[] { 1 });

        Jwe jwe = Jwe.builder()
            .withPayload(TestUtils.bytes(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21))
            .withProtectedHeader()
                .param(JweHeaderNames.ALGORITHM, "dir")
                .param(JweHeaderNames.ENCRYPTION_ALGORITHM, "A128GCM")
                .set()
            .withUnprotectedHeader()
                .param("x", 1)
                .set()
            .withRecipientHeader()
                .param("y", 2)
                .add()
            .withRecipientHeader()
                .param("z", 3)
                .add()
            .withAdditionalAuthenticatedData(TestUtils.bytes(0xAB))
            .allowedKeyAlgorithm(new DirectKeyAlgorithm(new SecretKeySpec(
                TestUtils.bytes(0x39, 0x3c, 0xa1, 0x5b, 0xec, 0x54, 0x1e, 0xff, 0x8c, 0xde, 0x67, 0xb9, 0x66, 0x9c, 0x2f, 0x3c), "AES")))
            .allowedEncryptionAlgorithm(new A128GcmEncryptionAlgorithm().useRandom(random))
            .serializedAs(JweSerialization.JSON)
            .useJsonConverter(new JacksonJson())
            .create();

        assertArrayEquals(TestUtils.bytes(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21), jwe.getPayload());
        assertEquals("dir", jwe.getProtectedHeader().get(JweHeaderNames.ALGORITHM));
        assertEquals("A128GCM", jwe.getProtectedHeader().get(JweHeaderNames.ENCRYPTION_ALGORITHM));
        assertEquals(Integer.valueOf(1), jwe.getUnprotectedHeader().get("x"));
        assertEquals(Integer.valueOf(2), jwe.getRecipientHeader(0).get("y"));
        assertEquals(Integer.valueOf(3), jwe.getRecipientHeader(1).get("z"));
        assertEquals("{\"protected\":\"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0\",\"unprotected\":{\"x\":1},\"recipients\":[{\"header\":{\"y\":2}},{\"header\":{\"z\":3}}],\"aad\":\"qw\",\"iv\":\"CisqglFlrpdCxjsM\",\"ciphertext\":\"ooTLw6K49EyaFphpVg\",\"tag\":\"RBIIDzevKfm7u39a7DjlTg\"}", jwe.asString());
    }
}
