package vn.iotstar.exception;

import java.io.Serial;

public class JwtInvalidSignatureException extends JwtAuthenticationException {

    @Serial
    private static final long serialVersionUID = 1L;

    public JwtInvalidSignatureException(String message) {
        super(message);
    }

    public JwtInvalidSignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
