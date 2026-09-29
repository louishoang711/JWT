package vn.iotstar.exception;

import java.io.Serial;

public abstract class JwtAuthenticationException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    protected JwtAuthenticationException(String message) {
        super(message);
    }

    protected JwtAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
