package ahodanenok.jose.jws.algorithm;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.function.Function;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JwsAlgorithmTest {

    @Test
    public void testNone() {
        NoneAlgorithm alg = new NoneAlgorithm();

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
        testHMAC("HmacSHA256", HS256Algorithm::new);
    }

    @Test
    public void testHS384() throws Exception {
        testHMAC("HmacSHA384", HS384Algorithm::new);
    }

    @Test
    public void testHS512() throws Exception {
        testHMAC("HmacSHA512", HS512Algorithm::new);
    }

    @Test
    public void testES256() throws Exception {
        testSignature("SHA256withECDSAinP1363Format", "EC", keys -> {
            ES256Algorithm alg = new ES256Algorithm();
            alg.signByPrivateKey(keys.getPrivate());
            alg.verifyByPublicKey(keys.getPublic());
            return alg;
        });
    }

    @Test
    public void testES384() throws Exception {
        testSignature("SHA384withECDSAinP1363Format", "EC", keys -> {
            ES384Algorithm alg = new ES384Algorithm();
            alg.signByPrivateKey(keys.getPrivate());
            alg.verifyByPublicKey(keys.getPublic());
            return alg;
        });
    }

    @Test
    public void testES512() throws Exception {
        testSignature("SHA512withECDSAinP1363Format", "EC", keys -> {
            ES512Algorithm alg = new ES512Algorithm();
            alg.signByPrivateKey(keys.getPrivate());
            alg.verifyByPublicKey(keys.getPublic());
            return alg;
        });
    }

    @Test
    public void testRS256() throws Exception {
        testSignature("SHA256withRSA", "RSASSA-PSS", keys -> {
            RS256Algorithm alg = new RS256Algorithm();
            alg.signByPrivateKey(keys.getPrivate());
            alg.verifyByPublicKey(keys.getPublic());
            return alg;
        });
    }

    @Test
    public void testRS384() throws Exception {
        testSignature("SHA384withRSA", "RSASSA-PSS", keys -> {
            RS384Algorithm alg = new RS384Algorithm();
            alg.signByPrivateKey(keys.getPrivate());
            alg.verifyByPublicKey(keys.getPublic());
            return alg;
        });
    }

    @Test
    public void testRS512() throws Exception {
        testSignature("SHA512withRSA", "RSASSA-PSS", keys -> {
            RS512Algorithm alg = new RS512Algorithm();
            alg.signByPrivateKey(keys.getPrivate());
            alg.verifyByPublicKey(keys.getPublic());
            return alg;
        });
    }

    public void testHMAC(String jcaAlgorithmName, Function<Key, JwsAlgorithm> algSupplier) throws Exception {
        Key key = KeyGenerator.getInstance(jcaAlgorithmName).generateKey();
        Mac mac = Mac.getInstance(jcaAlgorithmName);
        mac.init(key);
        JwsAlgorithm alg = algSupplier.apply(key);

        assertArrayEquals(mac.doFinal(new byte[0]), alg.sign(new byte[0]));
        assertTrue(alg.verify(new byte[0], mac.doFinal(new byte[0])));
        assertFalse(alg.verify(new byte[] { 1 }, mac.doFinal(new byte[0])));

        assertArrayEquals(mac.doFinal(new byte[] { 1, 2, 3}), alg.sign(new byte[] { 1, 2, 3 }));
        assertTrue(alg.verify(new byte[] { 1, 2, 3 }, mac.doFinal(new byte[] { 1, 2, 3 })));
        assertFalse(alg.verify(new byte[] { 1, 2, 3, 4 }, mac.doFinal(new byte[] { 1, 2, 3 })));
    }

    public void testSignature(
            String jcaSignatureAlgorithmName, String jcaKeyAlgorithmName,
            Function<KeyPair, JwsAlgorithm> algSupplier) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(jcaKeyAlgorithmName);
        KeyPair keys = keyGen.generateKeyPair();
        Signature sig = Signature.getInstance(jcaSignatureAlgorithmName);
        JwsAlgorithm alg = algSupplier.apply(keys);

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
