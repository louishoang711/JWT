package vn.iotstar.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BadCredentialsException.class)
    public ProblemDetail handleBadCredentials(BadCredentialsException exception) {
        return problem(HttpStatus.UNAUTHORIZED, "Invalid credentials", "Email hoặc mật khẩu không đúng.");
    }

    @ExceptionHandler(AccountStatusException.class)
    public ProblemDetail handleAccountStatus(AccountStatusException exception) {
        return problem(HttpStatus.FORBIDDEN, "Account unavailable", exception.getMessage());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedException exception) {
        return problem(HttpStatus.FORBIDDEN, "Forbidden", "You are not authorized to access this resource.");
    }

    @ExceptionHandler(JwtAuthenticationException.class)
    public ProblemDetail handleJwtAuthentication(JwtAuthenticationException exception) {
        return problem(HttpStatus.UNAUTHORIZED, "Invalid JWT", exception.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(IllegalArgumentException exception) {
        return problem(HttpStatus.BAD_REQUEST, "Invalid request", exception.getMessage());
    }

    private ProblemDetail problem(HttpStatus status, String title, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(title);
        return problem;
    }
}
