package ahodanenok.jose.jwe.algorithm;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import ahodanenok.jose.jwe.JweException;
import ahodanenok.jose.jwe.JweJoseHeader;

/**
 * Key Encryption with RSAES OAEP using SHA-256 and MGF1 with SHA-256
 */
public final class RsaOaep256KeyAlgorithm implements JweKeyAlgorithm {

    private final Cipher cipher;
    private PublicKey publicKey;
    private Certificate certificate;
    private PrivateKey privateKey;

    public RsaOaep256KeyAlgorithm() {
        try {
            this.cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
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
        return "RSA-OAEP-256";
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
                cipher.init(Cipher.WRAP_MODE, publicKey, getParam());
            } else if (certificate != null) {
                cipher.init(Cipher.WRAP_MODE, certificate.getPublicKey(), getParam());
            } else {
                throw new JweException("No public key provided to encrypt the key");
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
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
                cipher.init(Cipher.UNWRAP_MODE, privateKey, getParam());
            } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
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

    private OAEPParameterSpec getParam() {
        return new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT);
    }
}
