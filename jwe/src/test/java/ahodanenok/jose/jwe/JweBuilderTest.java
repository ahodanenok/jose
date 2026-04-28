package ahodanenok.jose.jwe;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import ahodanenok.jose.jwe.algorithm.A128GCMEncryptionAlgorithm;
import ahodanenok.jose.jwe.algorithm.DirectKeyAlgorithm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class JweBuilderTest {

    @Test
    public void testCompact_DirectEncryption() {
        Jwe jwe = Jwe.builder()
            .withPayload(TestUtils.bytes(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21))
            .withProtectedHeader()
                .param(JweHeaderNames.ALGORITHM, "dir")
                .param(JweHeaderNames.ENCRYPTION_ALGORITHM, "A128GCM")
                .set()
            .withAdditionalAuthenticatedData(TestUtils.bytes(0xAB))
            .allowedKeyAlgorithm(new DirectKeyAlgorithm(new SecretKeySpec(
                TestUtils.bytes(0x39, 0x3c, 0xa1, 0x5b, 0xec, 0x54, 0x1e, 0xff, 0x8c, 0xde, 0x67, 0xb9, 0x66, 0x9c, 0x2f, 0x3c), "AES")))
            .allowedEncryptionAlgorithm(new A128GCMEncryptionAlgorithm().useRandom(
                b -> TestUtils.fill(b, 0x41, 0x6f, 0x16, 0x60, 0xe6, 0xf4, 0x71, 0xed, 0x45, 0xe2, 0x35, 0xf5)))
            .serializedAs(JweSerialization.COMPACT)
            .useJsonConverter(new JacksonJson())
            .create();

        assertArrayEquals(TestUtils.bytes(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21), jwe.getPayload());
        assertEquals("dir", jwe.getProtectedHeader().get(JweHeaderNames.ALGORITHM));
        assertEquals("A128GCM", jwe.getProtectedHeader().get(JweHeaderNames.ENCRYPTION_ALGORITHM));
        assertEquals(null, jwe.getUnprotectedHeader());
        assertEquals("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..QW8WYOb0ce1F4jX1.VcTSRRHJU4thjUU57A.syIUfhOwkhNSIifh2d9XRw", jwe.asString());
    }

    @Test
    public void testJsonFlat_DirectEncryption() {
        Jwe jwe = Jwe.builder()
            .withPayload(TestUtils.bytes(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21))
            .withProtectedHeader()
                .param(JweHeaderNames.ALGORITHM, "dir")
                .param(JweHeaderNames.ENCRYPTION_ALGORITHM, "A128GCM")
                .set()
            .withAdditionalAuthenticatedData(TestUtils.bytes(0xAB))
            .allowedKeyAlgorithm(new DirectKeyAlgorithm(new SecretKeySpec(
                TestUtils.bytes(0x39, 0x3c, 0xa1, 0x5b, 0xec, 0x54, 0x1e, 0xff, 0x8c, 0xde, 0x67, 0xb9, 0x66, 0x9c, 0x2f, 0x3c), "AES")))
            .allowedEncryptionAlgorithm(new A128GCMEncryptionAlgorithm().useRandom(
                b -> TestUtils.fill(b, 0x41, 0x6f, 0x16, 0x60, 0xe6, 0xf4, 0x71, 0xed, 0x45, 0xe2, 0x35, 0xf5)))
            .serializedAs(JweSerialization.JSON_FLAT)
            .useJsonConverter(new JacksonJson())
            .create();

        assertArrayEquals(TestUtils.bytes(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21), jwe.getPayload());
        assertEquals("dir", jwe.getProtectedHeader().get(JweHeaderNames.ALGORITHM));
        assertEquals("A128GCM", jwe.getProtectedHeader().get(JweHeaderNames.ENCRYPTION_ALGORITHM));
        assertEquals(null, jwe.getUnprotectedHeader());
        assertEquals("{\"protected\":\"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0\",\"aad\":\"qw\",\"iv\":\"QW8WYOb0ce1F4jX1\",\"ciphertext\":\"VcTSRRHJU4thjUU57A\",\"tag\":\"syIUfhOwkhNSIifh2d9XRw\"}", jwe.asString());
    }
}
