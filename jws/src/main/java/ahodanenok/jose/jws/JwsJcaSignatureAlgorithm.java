package ahodanenok.jose.jws;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Objects;

abstract class JwsJcaSignatureAlgorithm implements JwsAlgorithm {

    private final String jwsAlgorithmName;
    private final Signature signer;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Certificate certificate;

    JwsJcaSignatureAlgorithm(String jwsAlgorithmName, String jcaAlgorithmName) {
        try {
            signer = Signature.getInstance(jcaAlgorithmName);
        } catch (NoSuchAlgorithmException e) {
            throw new JwsException("The algorithm '%s' is not supported".formatted(jwsAlgorithmName), e);
        }
        this.jwsAlgorithmName = jwsAlgorithmName;
    }

    JwsJcaSignatureAlgorithm(String jwsAlgorithmName, String jcaAlgorithmName, String provider) {
        try {
            signer = Signature.getInstance(jcaAlgorithmName, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new JwsException("The algorithm '%s' is not supported".formatted(jwsAlgorithmName), e);
        }
        this.jwsAlgorithmName = jwsAlgorithmName;
    }

    public final void signByPrivateKey(PrivateKey privateKey) {
        this.privateKey = Objects.requireNonNull(privateKey);
    }

    public final void verifyByPublicKey(PublicKey publicKey) {
        this.publicKey = Objects.requireNonNull(publicKey);
        this.certificate = null;
    }

    public void verifyByCertificate(Certificate certificate) {
        this.certificate = Objects.requireNonNull(certificate);
        this.publicKey = null;
    }

    @Override
    public final String getName() {
        return jwsAlgorithmName;
    }

    @Override
    public final byte[] sign(byte[] input) {
        if (privateKey == null) {
            throw new JwsException("No private key to sign the input");
        }

        try {
            signer.initSign(privateKey);
        } catch (InvalidKeyException e) {
            throw new JwsException("Failed to sign the input", e);
        }

        try {
            signer.update(input);
            return signer.sign();
        } catch (SignatureException e) {
            throw new JwsException("Failed to sign the input", e);
        }
    }

    @Override
    public final boolean verify(byte[] input, byte[] signature) {
        if (publicKey != null) {
            try {
                signer.initVerify(publicKey);
            } catch (InvalidKeyException e) {
                throw new JwsException("Failed to verify the signature", e);
            }
        } else if (certificate != null) {
            try {
                signer.initVerify(certificate);
            } catch (InvalidKeyException e) {
                throw new JwsException("Failed to verify the signature", e);
            }
        } else {
            throw new JwsException("No public key or certificate to verify the signature");
        }

        try {
            signer.update(input);
            return signer.verify(signature);
        } catch (SignatureException e) {
            throw new JwsException("Failed to verify the signature", e);
        }
    }
}