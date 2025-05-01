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
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.configuration.SecurityRealmConfigurationProperties;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Slf4j
public class SecurityRealmTokenCodec implements InitializingBean {

    private final String secret;
    private final Duration tokenExpirationDuration;
    private Algorithm algorithm;
    private JWTVerifier verifier;

    public SecurityRealmTokenCodec(SecurityRealmConfigurationProperties config) {
        this.secret = config.getSigningSecret();
        this.tokenExpirationDuration = config.getTokenExpirationDuration();
    }

    @Override
    public void afterPropertiesSet() {
        this.algorithm = Algorithm.HMAC512(secret);
        this.verifier = JWT.require(algorithm).build();
    }

    public String encode(SecurityRealmAuthentication authentication) {
        return JWT
            .create()
            .withSubject(authentication.getName())
            .withClaim("realm", authentication.getRealm())
            .withClaim("nextAuthenticationStep", authentication.getNextAuthenticationStep())
            .withClaim("authorities", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
            .withExpiresAt(Instant.now().plus(tokenExpirationDuration))
            .sign(algorithm);
    }

    public SecurityRealmAuthentication decode(String token) {
        try{
            DecodedJWT decodedJWT = verifier.verify(token);

            String realmName = decodedJWT.getClaim("realm").asString();
            String username = decodedJWT.getSubject();
            String nextAuthenticationStep = decodedJWT.getClaim("nextAuthenticationStep").asString();
            Set<GrantedAuthority> authorities = decodedJWT
                .getClaim("authorities")
                .asList(String.class)
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

            SecurityRealmAuthentication auth = new SecurityRealmAuthentication(username, authorities, nextAuthenticationStep);
            auth.setRealm(realmName);
            return auth;
        }catch(Exception e){
            return null;
        }
    }
}
