package ahodanenok.jose.jws;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JwsAlgorithmTest {

    @Test
    public void testNone() {
        NoneAlgoritm alg = new NoneAlgoritm();

        assertArrayEquals(new byte[0], alg.sign(new byte[0]));
        assertTrue(alg.verify(new byte[0], new byte[0]));
        assertFalse(alg.verify(new byte[0], new byte[] { 1 }));

        assertArrayEquals(new byte[0], alg.sign("abc".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(alg.verify("abc".getBytes(StandardCharsets.US_ASCII), new byte[0]));
        assertFalse(alg.verify("abc".getBytes(StandardCharsets.US_ASCII), new byte[] { 2 }));

        assertArrayEquals(new byte[0], alg.sign("UzI1NiJ9.0dHA6Ly9leGFt".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(alg.verify("UzI1NiJ9.0dHA6Ly9leGFt".getBytes(StandardCharsets.US_ASCII), new byte[0]));
        assertFalse(alg.verify("UzI1NiJ9.0dHA6Ly9leGFt".getBytes(StandardCharsets.US_ASCII), new byte[] { 3 }));
    }

    @Test
    public void testHS256() throws Exception {
        Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        HS256Algorithm alg = new HS256Algorithm(key);

        assertArrayEquals(mac.doFinal(new byte[0]), alg.sign(new byte[0]));
        assertTrue(alg.verify(new byte[0], mac.doFinal(new byte[0])));
        assertFalse(alg.verify(new byte[] { 1 }, mac.doFinal(new byte[0])));

        assertArrayEquals(mac.doFinal(new byte[] { 1, 2, 3}), alg.sign(new byte[] { 1, 2, 3 }));
        assertTrue(alg.verify(new byte[] { 1, 2, 3 }, mac.doFinal(new byte[] { 1, 2, 3 })));
        assertFalse(alg.verify(new byte[] { 1, 2, 3, 4 }, mac.doFinal(new byte[] { 1, 2, 3 })));
    }

    @Test
    public void testES256() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        KeyPair keys = keyGen.generateKeyPair();
        Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
        ES256Algorithm alg = new ES256Algorithm();
        alg.signByPrivateKey(keys.getPrivate());
        alg.verifyByPublicKey(keys.getPublic());

        byte[] signature;

        sig.initSign(keys.getPrivate());
        sig.update(new byte[0]);
        signature = sig.sign();
        assertTrue(alg.verify(new byte[0], signature));
        assertFalse(alg.verify(new byte[] { 1 }, signature));

        sig.initVerify(keys.getPublic());
        sig.update(new byte[0]);
        signature = alg.sign(new byte[0]);
        assertTrue(sig.verify(signature));
        sig.initVerify(keys.getPublic());
        sig.update(new byte[] { 1 });
        assertFalse(sig.verify(signature));

        sig.initSign(keys.getPrivate());
        sig.update(new byte[] { 1, 2, 3 });
        signature = sig.sign();
        assertTrue(alg.verify(new byte[] { 1, 2, 3 }, signature));
        assertFalse(alg.verify(new byte[] { 1, 2, 3, 4 }, signature));

        sig.initVerify(keys.getPublic());
        sig.update(new byte[] { 1, 2, 3 });
        signature = alg.sign(new byte[] { 1, 2, 3 });
        assertTrue(sig.verify(signature));
        sig.initVerify(keys.getPublic());
        sig.update(new byte[] { 1, 2, 3, 4 });
        assertFalse(sig.verify(signature));
    }
}
