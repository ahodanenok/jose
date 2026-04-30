package ahodanenok.jose.common;

import java.util.function.Supplier;

public final class Utils {

    public static void checkBounds(int idx, int from, int to) {
        checkBounds(idx, from, to, () -> "Index " + idx + " is not valid");
    }

    public static void checkBounds(
            int idx, int from, int to, Supplier<String> messageSupplier) {
        if (idx < from || idx >= to) {
            throw new IndexOutOfBoundsException(messageSupplier.get());
        }
    }
}
