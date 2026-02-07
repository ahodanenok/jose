package ahodanenok.jose.common;

/**
 * Base 64 Encoding with URL and Filename Safe Alphabet (with and without padding)
 *
 * @see https://datatracker.ietf.org/doc/html/rfc4648#section-5
 * @see https://datatracker.ietf.org/doc/html/rfc7515#appendix-C
 */
public final class Base64Url {

    private static final byte[] BYTES_EMPTY = new byte[0];
    private static final char[] ALPHABET = new char[] {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '-', '_'
    };
    private static final int[] ALPHABET_REVERSED;
    static {
        // Not using a map to avoid boxing/unboxing.
        // Allocate an array for all ascii characters
        // and set values only for those which are in the alphabet.
        ALPHABET_REVERSED = new int[128];
        for (int i = 0; i < ALPHABET_REVERSED.length; i++) {
            ALPHABET_REVERSED[i] = -1;
        }
        for (int i = 0; i < ALPHABET.length; i++) {
            ALPHABET_REVERSED[ALPHABET[i]] = i;
        }
    }

    public static String encode(byte[] data) {
        return encode(data, true);
    }

    public static String encode(byte[] data, boolean withPadding) {
        int n = data.length;
        if (n == 0) {
            return "";
        }

        int i = 3;
        StringBuilder sb = new StringBuilder();
        while (i <= n) {
            sb.append(ALPHABET[(data[i - 3] & 0xFC) >> 2]);
            sb.append(ALPHABET[((data[i - 3] & 0x03) << 4) | ((data[i - 2] & 0xF0) >> 4)]);
            sb.append(ALPHABET[((data[i - 2] & 0x0F) << 2) | ((data[i - 1] & 0xC0) >> 6)]);
            sb.append(ALPHABET[data[i - 1] & 0x3F]);
            i+= 3;
        }

        // handle non complete triple at the end
        i -= n;
        if (i == 1) { // two bytes left
            sb.append(ALPHABET[(data[n - 2] & 0xFC) >> 2]);
            sb.append(ALPHABET[((data[n - 2] & 0x03) << 4) | ((data[n - 1] & 0xF0) >> 4)]);
            sb.append(ALPHABET[(data[n - 1] & 0x0F) << 2]);
            if (withPadding) {
                sb.append("=");
            }
        } else if (i == 2) { // one byte left
            sb.append(ALPHABET[(data[n - 1] & 0xFC) >> 2]);
            sb.append(ALPHABET[(data[n - 1] & 0x03) << 4]);
            if (withPadding) {
                sb.append("==");
            }
        }

        return sb.toString();
    }

    public static byte[] decode(String string) {
        return decode(string, true);
    }

    public static byte[] decode(String string, boolean withPadding) {
        if (string.length() == 0) {
            return BYTES_EMPTY;
        }

        int n = string.length();
        if (withPadding) {
            if (string.charAt(n - 1) == '=') {
                n--;
                if (string.charAt(n - 1) == '=') {
                    n--;
                }
            }
        }

        int p = n % 4;
        if (p == 1) {
            // if the length of a string is not divisable by 4,
            // then it can only end in either 2 or 3 characters
            throw new IllegalArgumentException("Illegal base64url string");
        }

        int b; // output byte
        int c; // character's decoded value
        int j = 0;
        byte[] bytes = new byte[n / 4 * 3 + Math.max(0, (p - 1))];
        for (int i = 4; i <= n; i += 4) {
            c = decodeChar(string, i - 4);
            b = c << 2;
            c = decodeChar(string, i - 3);
            b |= c >> 4;
            bytes[j++] = (byte) b;

            b = (c & 0x0F) << 4;
            c = decodeChar(string, i - 2);
            b |= c >> 2;
            bytes[j++] = (byte) b;

            b = (c & 0x03) << 6;
            c = decodeChar(string, i - 1);
            b |= c;
            bytes[j++] = (byte) b;
        }

        if (p == 2) { // two characters left
            c = decodeChar(string, n - 2);
            b = c << 2;
            c = decodeChar(string, n - 1);
            b |= c >> 4;
            bytes[j++] = (byte) b;
        } else if (p == 3) { // three characters left
            c = decodeChar(string, n - 3);
            b = c << 2;
            c = decodeChar(string, n - 2);
            b |= c >> 4;
            bytes[j++] = (byte) b;

            b = (c & 0x0F) << 4;
            c = decodeChar(string, n - 1);
            b |= c >> 2;
            bytes[j++] = (byte) b;
        }

        return bytes;
    }

    private static int decodeChar(String string, int pos) {
        int c = ALPHABET_REVERSED[string.charAt(pos)];
        if (c == -1) {
            throw new IllegalArgumentException(
                "Illegal character at position %d: '%s'".formatted(pos, string.charAt(pos)));
        }

        return c;
    }
}
