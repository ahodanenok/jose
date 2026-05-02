package ahodanenok.jose.jwe.algorithm;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import ahodanenok.jose.jwe.JweException;
import ahodanenok.jose.jwe.JweJoseHeader;

public final class RsaPkcs1KeyAlgorithm implements JweKeyAlgorithm {

    private final Cipher cipher;
    private PublicKey publicKey;
    private Certificate certificate;
    private PrivateKey privateKey;

    public RsaPkcs1KeyAlgorithm() {
        try {
            this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new JweException("The algorithm '%s' is not supported".formatted(getName()), e);
        }
    }

    public void encryptWithPublicKey(PublicKey publicKey) {
        this.publicKey = Objects.requireNonNull(publicKey);
        this.certificate = null;
    }

    public void encryptWithCertificate(Certificate certificate) {
        this.certificate = Objects.requireNonNull(certificate);
        this.publicKey = null;
    }

    public void decryptWithPrivateKey(PrivateKey privateKey) {
        this.privateKey = Objects.requireNonNull(privateKey);
    }

    @Override
    public String getName() {
        return "RSA1_5";
    }

    @Override
    public KeyManagementMode getKeyManagementMode() {
        return KeyManagementMode.KEY_ENCRYPTION;
    }

    @Override
    public Object getKey(JweJoseHeader params) {
        return null;
    }

    @Override
    public byte[] encryptKey(Object key, JweJoseHeader params) {
        try {
            if (publicKey != null) {
                cipher.init(Cipher.WRAP_MODE, publicKey);
            } else if (certificate != null) {
                cipher.init(Cipher.WRAP_MODE, certificate);
            } else {
                throw new JweException("No public key provided to encrypt the key");
            }
        } catch (InvalidKeyException e) {
            throw new JweException("Failed to encrypt the key", e);
        }

        try {
            return cipher.wrap((Key) key);
        } catch (InvalidKeyException | IllegalBlockSizeException e) {
            throw new JweException("Failed to encrypt the key", e);
        }
    }

    @Override
    public Object decryptKey(byte[] key, String keyAlgorithmName, JweJoseHeader params) {
        if (privateKey != null) {
            try {
                cipher.init(Cipher.UNWRAP_MODE, privateKey);
            } catch (InvalidKeyException e) {
                throw new JweException("Failed to decrypt the key", e);
            }
        } else {
            throw new JweException("No private key provided to decrypt the key");
        }

        try {
            return cipher.unwrap(key, keyAlgorithmName, Cipher.SECRET_KEY);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new JweException("Failed to decrypt the key", e);
        }
    }
}
