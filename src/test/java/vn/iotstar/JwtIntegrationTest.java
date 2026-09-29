package vn.iotstar;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import vn.iotstar.entity.User;
import vn.iotstar.repository.UserRepository;
import vn.iotstar.services.JwtService;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JwtIntegrationTest {

    private static final String EMAIL = "student@hcmute.edu.vn";
    private static final String PASSWORD = "123456";
    private static final String TEST_SECRET = "Q2hhbmdlTWVfVGhpcy1Jcy1Pbkx5LURldi1TZWNyZXQ=";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private String token;

    @BeforeAll
    void clearDatabase() {
        userRepository.deleteAll();
    }

    @Test
    @Order(1)
    void aSignupStoresBcryptPassword() throws Exception {
        String request = """
                {
                  "email": "student@hcmute.edu.vn",
                  "password": "123456",
                  "fullName": "Nguyen Huu Trung"
                }
                """;

        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.fullName").value("Nguyen Huu Trung"))
                .andExpect(jsonPath("$.password").doesNotExist());

        User savedUser = userRepository.findByEmail(EMAIL).orElseThrow();
        assertThat(savedUser.getPassword()).startsWith("$2");
        assertThat(passwordEncoder.matches(PASSWORD, savedUser.getPassword())).isTrue();
    }

    @Test
    @Order(2)
    void bLoginReturnsNimbusHs256TokenWithRequiredClaims() throws Exception {
        String request = """
                {
                  "email": "student@hcmute.edu.vn",
                  "password": "123456"
                }
                """;

        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expiresIn").value(3600000))
                .andReturn();

        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        token = body.get("token").asText();

        SignedJWT parsed = SignedJWT.parse(token);
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        assertThat(parsed.getHeader().getType()).isEqualTo(JOSEObjectType.JWT);
        assertThat(parsed.getJWTClaimsSet().getSubject()).isEqualTo(EMAIL);
        assertThat(parsed.getJWTClaimsSet().getIssueTime()).isNotNull();
        assertThat(parsed.getJWTClaimsSet().getExpirationTime()).isAfter(new Date());
    }

    @Test
    @Order(3)
    void cUsersMeWithoutTokenReturns401() throws Exception {
        mockMvc.perform(get("/users/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.detail").exists());
    }

    @Test
    @Order(4)
    void dUsersMeWithValidTokenReturnsCurrentUser() throws Exception {
        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.fullName").value("Nguyen Huu Trung"));
    }

    @Test
    @Order(5)
    void eUsersWithValidTokenReturnsList() throws Exception {
        mockMvc.perform(get("/users")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].email").value(EMAIL));
    }

    @Test
    @Order(6)
    void fWrongPasswordReturns401() throws Exception {
        String request = """
                {
                  "email": "student@hcmute.edu.vn",
                  "password": "wrong-password"
                }
                """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.title").value("Invalid credentials"));
    }

    @Test
    @Order(7)
    void gTamperedSignatureReturns401() throws Exception {
        int signatureStart = token.lastIndexOf('.') + 1;
        char replacement = token.charAt(signatureStart) == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, signatureStart)
                + replacement
                + token.substring(signatureStart + 1);

        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.title").value("Invalid JWT"))
                .andExpect(jsonPath("$.detail").value("JWT signature is invalid"));
    }

    @Test
    @Order(8)
    void hMalformedTokenReturns401InsteadOf500() throws Exception {
        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer dfdfdfdfd"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.title").value("Invalid JWT"))
                .andExpect(jsonPath("$.detail").value("JWT token is malformed"));
    }

    @Test
    @Order(9)
    void iExpiredTokenReturns401() throws Exception {
        User user = userRepository.findByEmail(EMAIL).orElseThrow();
        JwtService expiredTokenService = new JwtService(TEST_SECRET, -1_000);
        String expiredToken = expiredTokenService.generateToken(user);

        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.title").value("Invalid JWT"))
                .andExpect(jsonPath("$.detail").value("JWT token has expired"));
    }

    @Test
    @Order(10)
    void jAuthenticationDoesNotCreateHttpSession() throws Exception {
        MvcResult result = mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getRequest().getSession(false)).isNull();
    }

    @Test
    @Order(11)
    void kThymeleafPagesArePublic() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Đăng nhập")));

        mockMvc.perform(get("/signup"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Đăng ký")));

        mockMvc.perform(get("/user/profile"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Thông tin người dùng")));
    }
}
