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
        assertEquals(true, input.isRecipientValid());
        assertEquals(true, input.isRecipientValid(0));
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

    @Test
    public void testParseJson() throws Exception {
        // https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.4
        JweParser parser = JweParser.builder()
            .forSerialization(JweSerialization.JSON)
            .alloweKeyAlgorithm(new A128KwKeyAlgorithm(new SecretKeySpec(TestUtils.bytes(0x19, 0xac, 0x20, 0x82, 0xe1, 0x72, 0x1a, 0xb5, 0x8a, 0x6a, 0xfe, 0xc0, 0x5f, 0x85, 0x4a, 0x52), "AES")))
            .allowedEncryptionAlgorithm(new A128CbcHS256EncryptionAlgorithm(null))
            .withJsonParser(new JacksonJson())
            .build();

        JweInput input = parser.parse("""
        {
            "protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
            "unprotected":{"jku":"https://server.example.com/keys.jwks"},
            "recipients":[
                {"header":{"alg":"RSA1_5","kid":"2011-04-29"},
                 "encrypted_key":"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},
                {"header":{"alg":"A128KW","kid":"7"},
                "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}
            ],
            "iv":"AxY8DCtDaGlsbGljb3RoZQ",
            "ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
            "tag":"Mz-VPPyU4RlcuYv1IwIvzw"
        }
        """);
        assertEquals(false, input.isRecipientValid());
        assertEquals(false, input.isRecipientValid(0));
        assertEquals(true, input.isRecipientValid(1));
        assertEquals("Live long and prosper.", new String(input.getPayload(), "UTF-8"));
        assertEquals("A128CBC-HS256", input.getProtectedHeader().getEncryptionAlgorithm());
        assertEquals("https://server.example.com/keys.jwks", input.getUnprotectedHeader().get("jku"));
        assertEquals("RSA1_5", input.getRecipientHeader(0).getKeyAlgorithm());
        assertEquals("2011-04-29", input.getRecipientHeader(0).get("kid"));
        assertEquals("A128KW", input.getRecipientHeader(1).getKeyAlgorithm());
        assertEquals("7", input.getRecipientHeader(1).get("kid"));
        assertEquals(2, input.getRecipientCount());

        Jwe jwe = input.accept();
        assertEquals("Live long and prosper.", new String(jwe.getPayload(), "UTF-8"));
        assertEquals("A128CBC-HS256", jwe.getProtectedHeader().getEncryptionAlgorithm());
        assertEquals("https://server.example.com/keys.jwks", jwe.getUnprotectedHeader().get("jku"));
        assertEquals("RSA1_5", jwe.getRecipientHeader(0).getKeyAlgorithm());
        assertEquals("2011-04-29", jwe.getRecipientHeader(0).get("kid"));
        assertEquals("A128KW", jwe.getRecipientHeader(1).getKeyAlgorithm());
        assertEquals("7", jwe.getRecipientHeader(1).get("kid"));
        assertEquals(2, jwe.getRecipientCount());
    }
}
