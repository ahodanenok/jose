// package ahodanenok.jose.jws;

// import java.util.HashMap;
// import java.util.Map;

// public final class RfcJwsSigner implements JwsSigner {

//     static final RfcJwsSigner DEFAULT_INSTANCE;
//     static {
//         DEFAULT_INSTANCE = new RfcJwsSigner();
//         DEFAULT_INSTANCE.register(new NoneAlgoritm());
//     }

//     private final Map<String, JwsAlgoritm> algorithms;

//     public RfcJwsSigner() {
//         algorithms = new HashMap<>();
//     }

//     public void register(JwsAlgoritm algorithm) {
//         // todo: check already registered?
//         algorithms.put(algorithm.getName(), algorithm);
//     }

//     @Override
//     public byte[] sign(byte[] input, String algorithmName) {
//         JwsAlgoritm algorithm = algorithms.get(algorithmName);
//         // todo: error if null

//         return algorithm.sign(input);
//     }
// }
