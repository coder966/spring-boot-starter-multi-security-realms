package net.coder966.spring.multisecurityrealms.converter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class SecurityRealmTokenCodec {

    private final Duration ttl;
    private final Algorithm algorithm;
    private final JWTVerifier verifier;

    public SecurityRealmTokenCodec(String secret, Duration ttl) {
        this.ttl = ttl;
        this.algorithm = Algorithm.HMAC512(secret);
        this.verifier = JWT.require(algorithm).build();
    }

    public String encode(SecurityRealmAuthentication authentication) {
        return JWT
            .create()
            .withClaim("realm", authentication.getRealm())

            .withSubject(authentication.getName())
            .withClaim("authorities", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))

            .withClaim("nextAuthenticationStep", authentication.getNextAuthenticationStep())

            .withExpiresAt(Instant.now().plus(ttl))
            .sign(algorithm);
    }

    public SecurityRealmAuthentication decode(String token) {
        try{
            DecodedJWT decodedJWT = verifier.verify(token);

            String realmName = decodedJWT.getClaim("realm").asString();

            String username = decodedJWT.getSubject();
            Set<GrantedAuthority> authorities = decodedJWT
                .getClaim("authorities")
                .asList(String.class)
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

            String nextAuthenticationStep = decodedJWT.getClaim("nextAuthenticationStep").asString();

            SecurityRealmAuthentication auth = new SecurityRealmAuthentication(username, authorities, nextAuthenticationStep);

            auth._UNSAFE_overrideRealm(realmName);
            return auth;
        }catch(Exception e){
            return null;
        }
    }
}
