package ahodanenok.jose.jws;

import java.util.function.Supplier;

class Utils {

    static void checkBounds(
            int idx, int from, int to, Supplier<String> messageSupplier) {
        if (idx < from || idx >= to) {
            throw new IndexOutOfBoundsException(messageSupplier.get());
        }
    }
}
