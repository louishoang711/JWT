package vn.iotstar.exception;

import java.io.Serial;

public class JwtExpiredException extends JwtAuthenticationException {

    @Serial
    private static final long serialVersionUID = 1L;

    public JwtExpiredException(String message) {
        super(message);
    }
}
