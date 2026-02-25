package ahodanenok.jose.jws;

/**
 * No digital signature or MAC performed
 */
public final class NoneAlgorithm implements JwsAlgorithm {

    public static final NoneAlgorithm INSTANCE = new NoneAlgorithm();
    static final String NAME = "none";

    private static final byte[] SIGNATURE = new byte[0];

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public byte[] sign(byte[] input) {
        return SIGNATURE;
    }

    @Override
    public boolean verify(byte[] input, byte[] signature) {
        return signature.length == 0;
    }
}
