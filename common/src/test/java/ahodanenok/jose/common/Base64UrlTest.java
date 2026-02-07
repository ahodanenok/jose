package ahodanenok.jose.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class Base64UrlTest {

    @Test
    public void testEncodeAlphabet() {
        assertEquals("ABCD", Base64Url.encode(bytes(0x00, 0x10, 0x83)));
        assertEquals("EFGH", Base64Url.encode(bytes(0x10, 0x51, 0x87)));
        assertEquals("IJKL", Base64Url.encode(bytes(0x20, 0x92, 0x8B)));
        assertEquals("MNOP", Base64Url.encode(bytes(0x30, 0xD3, 0x8F)));
        assertEquals("QRST", Base64Url.encode(bytes(0x41, 0x14, 0x93)));
        assertEquals("UVWX", Base64Url.encode(bytes(0x51, 0x55, 0x97)));
        assertEquals("YZab", Base64Url.encode(bytes(0x61, 0x96, 0x9B)));
        assertEquals("cdef", Base64Url.encode(bytes(0x71, 0xD7, 0x9F)));
        assertEquals("ghij", Base64Url.encode(bytes(0x82, 0x18, 0xA3)));
        assertEquals("klmn", Base64Url.encode(bytes(0x92, 0x59, 0xA7)));
        assertEquals("opqr", Base64Url.encode(bytes(0xA2, 0x9A, 0xAB)));
        assertEquals("stuv", Base64Url.encode(bytes(0xB2, 0xDB, 0xAF)));
        assertEquals("wxyz", Base64Url.encode(bytes(0xC3, 0x1C, 0xB3)));
        assertEquals("0123", Base64Url.encode(bytes(0xD3, 0x5D, 0xB7)));
        assertEquals("4567", Base64Url.encode(bytes(0xE3, 0x9E, 0xBB)));
        assertEquals("89-_", Base64Url.encode(bytes(0xF3, 0xDF, 0xBF)));
    }

    @Test
    public void testEncodeWithPadding() {
        assertEquals("", Base64Url.encode(new byte[0]));
        assertEquals("Zg==", Base64Url.encode(bytes(0x66)));
        assertEquals("Zm8=", Base64Url.encode(bytes(0x66, 0x6F)));
        assertEquals("Zm9v", Base64Url.encode(bytes(0x66, 0x6F, 0x6F)));
        assertEquals("Zm9vYg==", Base64Url.encode(bytes(0x66, 0x6F, 0x6F, 0x62)));
        assertEquals("Zm9vYmE=", Base64Url.encode(bytes(0x66, 0x6F, 0x6F, 0x62, 0x61)));
        assertEquals("Zm9vYmFy", Base64Url.encode(bytes(0x66, 0x6F, 0x6F, 0x62, 0x61, 0x72)));
        assertEquals("A-z_4ME=", Base64Url.encode(bytes(0x03, 0xEC, 0xFF, 0xE0, 0xC1)));
        assertEquals("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", Base64Url.encode(bytes(0x7B, 0x22, 0x74, 0x79, 0x70, 0x22, 0x3A, 0x22, 0x4A, 0x57, 0x54, 0x22, 0x2C, 0x0D, 0x0A, 0x20, 0x22, 0x61, 0x6C, 0x67, 0x22, 0x3A, 0x22, 0x48, 0x53, 0x32, 0x35, 0x36, 0x22, 0x7D)));
    }

    @Test
    public void testEncodeWithoutPadding() {
        assertEquals("", Base64Url.encode(new byte[0], false));
        assertEquals("Zg", Base64Url.encode(bytes(0x66), false));
        assertEquals("Zm8", Base64Url.encode(bytes(0x66, 0x6F), false));
        assertEquals("Zm9v", Base64Url.encode(bytes(0x66, 0x6F, 0x6F), false));
        assertEquals("Zm9vYg", Base64Url.encode(bytes(0x66, 0x6F, 0x6F, 0x62), false));
        assertEquals("Zm9vYmE", Base64Url.encode(bytes(0x66, 0x6F, 0x6F, 0x62, 0x61), false));
        assertEquals("Zm9vYmFy", Base64Url.encode(bytes(0x66, 0x6F, 0x6F, 0x62, 0x61, 0x72), false));
        assertEquals("A-z_4ME", Base64Url.encode(bytes(0x03, 0xEC, 0xFF, 0xE0, 0xC1), false));
        assertEquals("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", Base64Url.encode(bytes(0x7B, 0x22, 0x74, 0x79, 0x70, 0x22, 0x3A, 0x22, 0x4A, 0x57, 0x54, 0x22, 0x2C, 0x0D, 0x0A, 0x20, 0x22, 0x61, 0x6C, 0x67, 0x22, 0x3A, 0x22, 0x48, 0x53, 0x32, 0x35, 0x36, 0x22, 0x7D), false));
    }

    @Test
    public void testDecodeAlphabet() {
        assertArrayEquals(bytes(0x00, 0x10, 0x83), Base64Url.decode("ABCD"));
        assertArrayEquals(bytes(0x10, 0x51, 0x87), Base64Url.decode("EFGH"));
        assertArrayEquals(bytes(0x20, 0x92, 0x8B), Base64Url.decode("IJKL"));
        assertArrayEquals(bytes(0x30, 0xD3, 0x8F), Base64Url.decode("MNOP"));
        assertArrayEquals(bytes(0x41, 0x14, 0x93), Base64Url.decode("QRST"));
        assertArrayEquals(bytes(0x51, 0x55, 0x97), Base64Url.decode("UVWX"));
        assertArrayEquals(bytes(0x61, 0x96, 0x9B), Base64Url.decode("YZab"));
        assertArrayEquals(bytes(0x71, 0xD7, 0x9F), Base64Url.decode("cdef"));
        assertArrayEquals(bytes(0x82, 0x18, 0xA3), Base64Url.decode("ghij"));
        assertArrayEquals(bytes(0x92, 0x59, 0xA7), Base64Url.decode("klmn"));
        assertArrayEquals(bytes(0xA2, 0x9A, 0xAB), Base64Url.decode("opqr"));
        assertArrayEquals(bytes(0xB2, 0xDB, 0xAF), Base64Url.decode("stuv"));
        assertArrayEquals(bytes(0xC3, 0x1C, 0xB3), Base64Url.decode("wxyz"));
        assertArrayEquals(bytes(0xD3, 0x5D, 0xB7), Base64Url.decode("0123"));
        assertArrayEquals(bytes(0xE3, 0x9E, 0xBB), Base64Url.decode("4567"));
        assertArrayEquals(bytes(0xF3, 0xDF, 0xBF), Base64Url.decode("89-_"));
    }

    @Test
    public void testDecodeWithPadding() {
        assertArrayEquals(new byte[0], Base64Url.decode(""));
        assertArrayEquals(bytes(0x66), Base64Url.decode("Zg=="));
        assertArrayEquals(bytes(0x66, 0x6F), Base64Url.decode("Zm8="));
        assertArrayEquals(bytes(0x66, 0x6F, 0x6F), Base64Url.decode("Zm9v"));
        assertArrayEquals(bytes(0x66, 0x6F, 0x6F, 0x62), Base64Url.decode("Zm9vYg=="));
        assertArrayEquals(bytes(0x66, 0x6F, 0x6F, 0x62, 0x61), Base64Url.decode("Zm9vYmE="));
        assertArrayEquals(bytes(0x66, 0x6F, 0x6F, 0x62, 0x61, 0x72), Base64Url.decode("Zm9vYmFy"));
        assertArrayEquals(bytes(0x03, 0xEC, 0xFF, 0xE0, 0xC1), Base64Url.decode("A-z_4ME="));
        assertArrayEquals(bytes(0x7B, 0x22, 0x74, 0x79, 0x70, 0x22, 0x3A, 0x22, 0x4A, 0x57, 0x54, 0x22, 0x2C, 0x0D, 0x0A, 0x20, 0x22, 0x61, 0x6C, 0x67, 0x22, 0x3A, 0x22, 0x48, 0x53, 0x32, 0x35, 0x36, 0x22, 0x7D), Base64Url.decode("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"));
    }

    @Test
    public void testDecodeWithoutPadding() {
        assertArrayEquals(new byte[0], Base64Url.decode("", false));
        assertArrayEquals(bytes(0x66), Base64Url.decode("Zg", false));
        assertArrayEquals(bytes(0x66, 0x6F), Base64Url.decode("Zm8", false));
        assertArrayEquals(bytes(0x66, 0x6F, 0x6F), Base64Url.decode("Zm9v", false));
        assertArrayEquals(bytes(0x66, 0x6F, 0x6F, 0x62), Base64Url.decode("Zm9vYg", false));
        assertArrayEquals(bytes(0x66, 0x6F, 0x6F, 0x62, 0x61), Base64Url.decode("Zm9vYmE", false));
        assertArrayEquals(bytes(0x66, 0x6F, 0x6F, 0x62, 0x61, 0x72), Base64Url.decode("Zm9vYmFy", false));
        assertArrayEquals(bytes(0x03, 0xEC, 0xFF, 0xE0, 0xC1), Base64Url.decode("A-z_4ME", false));
        assertArrayEquals(bytes(0x7B, 0x22, 0x74, 0x79, 0x70, 0x22, 0x3A, 0x22, 0x4A, 0x57, 0x54, 0x22, 0x2C, 0x0D, 0x0A, 0x20, 0x22, 0x61, 0x6C, 0x67, 0x22, 0x3A, 0x22, 0x48, 0x53, 0x32, 0x35, 0x36, 0x22, 0x7D), Base64Url.decode("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", false));
    }

    private static byte[] bytes(int... bytes) {
        byte[] buf = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            buf[i] = (byte) bytes[i];
        }

        return buf;
    }
}
