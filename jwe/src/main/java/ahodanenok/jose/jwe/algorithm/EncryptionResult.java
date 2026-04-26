package ahodanenok.jose.jwe.algorithm;

public record EncryptionResult(byte[] ciphertext, byte[] authenticationTag) { };
