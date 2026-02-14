package ahodanenok.jose.jws;

import ahodanenok.jose.common.JoseException;

public abstract class JwsAlgoritmBase implements JwsAlgoritm {

    @Override
    public final byte[] sign(byte[] input) {
        try {
            return doSign(input);
        } catch (JoseException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new JwsException(
                "Failed to sign input with '%s' algorithm".formatted(getName()),
                e);
        }
    }

    protected abstract byte[] doSign(byte[] input) throws Exception;
}
