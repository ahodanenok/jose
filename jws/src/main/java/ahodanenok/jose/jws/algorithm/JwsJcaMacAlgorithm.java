package ahodanenok.jose.jws.algorithm;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.Mac;

import ahodanenok.jose.jws.JwsException;

abstract class JwsJcaMacAlgorithm implements JwsAlgorithm {

    private final Mac mac;
    private final Key secretKey;
    private final String jwsAlgorithmName;

    protected JwsJcaMacAlgorithm(String jwsAlgorithmName, String jcaAlgorithmName, Key secretKey) {
        try {
            this.mac = Mac.getInstance(jcaAlgorithmName);
        } catch (NoSuchAlgorithmException e) {
            throw new JwsException("The algorithm '%s' is not supported".formatted(jwsAlgorithmName), e);
        }
        try {
            mac.init(secretKey);
        } catch (InvalidKeyException e) {
            throw new JwsException("Key is not valid", e);
        }
        this.secretKey = Objects.requireNonNull(secretKey);
        this.jwsAlgorithmName = jwsAlgorithmName;
    }

    protected JwsJcaMacAlgorithm(String jwsAlgorithmName, String jcaAlgorithmName, Key secretKey, String provider) {
        try {
            this.mac = Mac.getInstance(jcaAlgorithmName, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new JwsException("The algorithm '%s' is not supported".formatted(jwsAlgorithmName), e);
        }
        try {
            mac.init(secretKey);
        } catch (InvalidKeyException e) {
            throw new JwsException("Key is not valid", e);
        }
        this.secretKey = Objects.requireNonNull(secretKey);
        this.jwsAlgorithmName = jwsAlgorithmName;
    }

    public String getName() {
        return jwsAlgorithmName;
    }

    @Override
    public byte[] sign(byte[] input) {
        return mac.doFinal(input);
    }

    @Override
    public boolean verify(byte[] input, byte[] signature) {
        return Arrays.equals(sign(input), signature);
    }
}
