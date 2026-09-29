package vn.iotstar.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import vn.iotstar.exception.JwtExpiredException;
import vn.iotstar.exception.JwtInvalidSignatureException;
import vn.iotstar.exception.JwtMalformedException;

import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    private final byte[] secretBytes;
    private final long jwtExpiration;

    public JwtService(
            @Value("${security.jwt.secret-key}") String secretKey,
            @Value("${security.jwt.expiration-time}") long jwtExpiration
    ) {
        this.secretBytes = decodeSecret(secretKey);
        this.jwtExpiration = jwtExpiration;
    }

    public String extractUsername(String token) {
        return parseAndVerify(token).getSubject();
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        Date issuedAt = new Date();
        Date expiration = new Date(issuedAt.getTime() + jwtExpiration);

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder();
        extraClaims.forEach(claimsBuilder::claim);

        JWTClaimsSet claims = claimsBuilder
                .subject(userDetails.getUsername())
                .issueTime(issuedAt)
                .expirationTime(expiration)
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256)
                        .type(JOSEObjectType.JWT)
                        .build(),
                claims
        );

        try {
            signedJWT.sign(new MACSigner(secretBytes));
            return signedJWT.serialize();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Could not sign JWT", exception);
        }
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        JWTClaimsSet claims = parseAndVerify(token);
        String subject = claims.getSubject();
        Date expiration = claims.getExpirationTime();

        if (subject == null || subject.isBlank()) {
            throw new JwtMalformedException("JWT subject is missing");
        }
        if (expiration == null) {
            throw new JwtMalformedException("JWT expiration is missing");
        }
        if (!expiration.after(new Date())) {
            throw new JwtExpiredException("JWT token has expired");
        }

        return subject.equals(userDetails.getUsername());
    }

    public Date extractExpiration(String token) {
        Date expiration = parseAndVerify(token).getExpirationTime();
        if (expiration == null) {
            throw new JwtMalformedException("JWT expiration is missing");
        }
        return expiration;
    }

    private JWTClaimsSet parseAndVerify(String token) {
        final SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (ParseException | IllegalArgumentException exception) {
            throw new JwtMalformedException("JWT token is malformed", exception);
        }

        if (!JWSAlgorithm.HS256.equals(signedJWT.getHeader().getAlgorithm())) {
            throw new JwtInvalidSignatureException("JWT must use the HS256 algorithm");
        }

        try {
            if (!signedJWT.verify(new MACVerifier(secretBytes))) {
                throw new JwtInvalidSignatureException("JWT signature is invalid");
            }
            return signedJWT.getJWTClaimsSet();
        } catch (JOSEException exception) {
            throw new JwtInvalidSignatureException("JWT signature could not be verified", exception);
        } catch (ParseException exception) {
            throw new JwtMalformedException("JWT claims are malformed", exception);
        }
    }

    private byte[] decodeSecret(String secretKey) {
        final byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(secretKey);
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("security.jwt.secret-key must be valid Base64", exception);
        }

        if (decoded.length < 32) {
            throw new IllegalStateException("HS256 requires a secret of at least 256 bits");
        }
        return decoded;
    }
}
