package ahodanenok.jose.jwe;

public class TestUtils {

    public static byte[] bytes(int... bytes) {
        byte[] buf = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            buf[i] = (byte) bytes[i];
        }

        return buf;
    }

    public static byte[] fill(byte[] array, int... bytes) {
        if (array.length != bytes.length) {
            throw new IllegalArgumentException("Lengths don't match");
        }

        for (int i = 0; i < array.length; i++) {
            array[i] = (byte) bytes[i];
        }

        return array;
    }
}
