package vn.iotstar.services;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.iotstar.entity.User;
import vn.iotstar.models.LoginUserModel;
import vn.iotstar.models.RegisterUserModel;
import vn.iotstar.repository.UserRepository;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(
            UserRepository userRepository,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User signup(RegisterUserModel input) {
        String email = input.getEmail() == null ? "" : input.getEmail().trim();
        String fullName = input.getFullName() == null ? "" : input.getFullName().trim();
        String password = input.getPassword() == null ? "" : input.getPassword();

        if (fullName.isBlank() || email.isBlank() || password.isBlank()) {
            throw new IllegalArgumentException("Vui lòng nhập đầy đủ thông tin.");
        }
        if (password.length() < 6) {
            throw new IllegalArgumentException("Mật khẩu phải có ít nhất 6 ký tự.");
        }
        if (userRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("Email đã được đăng ký.");
        }

        User user = new User();
        user.setFullName(fullName);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));

        return userRepository.save(user);
    }

    public User authenticate(LoginUserModel input) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(input.getEmail(), input.getPassword())
        );

        return userRepository.findByEmail(input.getEmail()).orElseThrow();
    }
}
