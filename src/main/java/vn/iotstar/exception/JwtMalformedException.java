package vn.iotstar.exception;

import java.io.Serial;

public class JwtMalformedException extends JwtAuthenticationException {

    @Serial
    private static final long serialVersionUID = 1L;

    public JwtMalformedException(String message) {
        super(message);
    }

    public JwtMalformedException(String message, Throwable cause) {
        super(message, cause);
    }
}
