package ahodanenok.jose.jwe.algorithm;

public record DecryptionResult(byte[] plaintext, boolean authenticated) { };
