package net.coder966.spring.multisecurityrealms.converter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Slf4j
public class AuthenticationTokenConverter {

    private final Algorithm algorithm;
    private final JWTVerifier verifier;
    private final Duration tokenExpirationDuration;

    public AuthenticationTokenConverter(String secret, Duration tokenExpirationDuration) {
        this.algorithm = Algorithm.HMAC512(secret);
        this.verifier = JWT.require(algorithm).build();
        this.tokenExpirationDuration = tokenExpirationDuration;
    }

    public String createToken(SecurityRealmAuthentication authentication) {
        return JWT
            .create()
            .withSubject(authentication.getName())
            .withClaim("realm", authentication.getRealmName())
            .withClaim("nextAuthStep", authentication.getNextAuthStep())
            .withClaim("authorities", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
            .withExpiresAt(Instant.now().plus(tokenExpirationDuration))
            .sign(algorithm);
    }

    public SecurityRealmAuthentication verifyToken(String token) {
        try{
            DecodedJWT decodedJWT = verifier.verify(token);

            String nextAuthStep = decodedJWT.getClaim("nextAuthStep").asString();
            String realmName = decodedJWT.getClaim("realm").asString();
            String username = decodedJWT.getSubject();
            Set<GrantedAuthority> authorities = decodedJWT
                .getClaim("authorities")
                .asList(String.class)
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

            SecurityRealmAuthentication authentication = new SecurityRealmAuthentication(username, authorities, nextAuthStep);
            authentication.setRealmName(realmName);
            return authentication;
        }catch(Exception e){
            return null;
        }
    }
}
