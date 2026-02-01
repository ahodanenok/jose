package ahodanenok.jose.jws;

public final class NoneAlgoritm implements JwsAlgoritm {

    private static final byte[] SIGNATURE = new byte[0];

    @Override
    public String getName() {
        return "none";
    }

    @Override
    public byte[] sign(String input) {
        return SIGNATURE;
    }
}
