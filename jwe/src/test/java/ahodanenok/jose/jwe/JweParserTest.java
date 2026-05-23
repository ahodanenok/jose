package ahodanenok.jose.jwe;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import ahodanenok.jose.jwe.algorithm.A128CbcHS256EncryptionAlgorithm;
import ahodanenok.jose.jwe.algorithm.A128KwKeyAlgorithm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class JweParserTest {

    @Test
    public void testParseCompact() throws Exception {
        // https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.3
        JweParser parser = JweParser.builder()
            .forSerialization(JweSerialization.COMPACT)
            .alloweKeyAlgorithm(new A128KwKeyAlgorithm(new SecretKeySpec(TestUtils.bytes(0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5, 0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52), "AES")))
            .allowedEncryptionAlgorithm(new A128CbcHS256EncryptionAlgorithm(null))
            .withJsonParser(new JacksonJson())
            .build();

        JweInput input = parser.parse("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ");
        assertEquals(true, input.isValid());
        assertEquals("Live long and prosper.", new String(input.getPayload(), "UTF-8"));
        assertEquals("A128KW", input.getProtectedHeader().getKeyAlgorithm());
        assertEquals("A128CBC-HS256", input.getProtectedHeader().getEncryptionAlgorithm());
        assertEquals(null, input.getUnprotectedHeader());
        assertEquals(null, input.getRecipientHeader());
        assertEquals(1, input.getRecipientCount());

        Jwe jwe = input.accept();
        assertEquals("Live long and prosper.", new String(jwe.getPayload(), "UTF-8"));
        assertEquals("A128KW", jwe.getProtectedHeader().getKeyAlgorithm());
        assertEquals("A128CBC-HS256", jwe.getProtectedHeader().getEncryptionAlgorithm());
        assertEquals(null, jwe.getUnprotectedHeader());
        assertEquals(null, jwe.getRecipientHeader());
        assertEquals(1, jwe.getRecipientCount());
    }
}
