package ahodanenok.jose.jwe;

public interface JweJoseHeader {

    String getKeyAlgorithm();

    String getEncryptionAlgorithm();

    <T> T get(String name);
}
