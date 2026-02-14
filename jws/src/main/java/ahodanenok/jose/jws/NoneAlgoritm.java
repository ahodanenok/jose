package ahodanenok.jose.jws;

public final class NoneAlgoritm implements JwsAlgoritm {

    public static final NoneAlgoritm INSTANCE = new NoneAlgoritm();
    public static final String NAME = "none";

    private static final byte[] SIGNATURE = new byte[0];

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public byte[] sign(byte[] input) {
        return SIGNATURE;
    }
}
