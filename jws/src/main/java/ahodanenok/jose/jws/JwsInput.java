package ahodanenok.jose.jws;

import java.util.List;

public interface JwsInput {

    byte[] getPayload();

    JwsHeader getProtectedHeader();

    JwsHeader getProtectedHeader(int idx);

    byte[] getSignature();

    byte[] getSignature(int idx);

    boolean isValid();

    List<Integer> getInvalidSignatures();

    Jws accept();
}
