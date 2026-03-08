package ahodanenok.jose.jws;

interface JwsJoseHeader {

    String getAlgorithm();

    <T> T get(String name);
}
