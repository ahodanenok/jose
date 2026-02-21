package ahodanenok.jose.jws;

class TestUtils {

    static byte[] bytes(int... bytes) {
        byte[] buf = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            buf[i] = (byte) bytes[i];
        }

        return buf;
    }
}
