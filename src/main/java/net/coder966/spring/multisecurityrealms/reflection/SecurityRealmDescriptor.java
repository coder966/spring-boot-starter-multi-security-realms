package net.coder966.spring.multisecurityrealms.reflection;

import net.coder966.spring.multisecurityrealms.converter.SecurityRealmTokenCodec;
import org.springframework.security.web.util.matcher.RequestMatcher;
import java.time.Duration;

public class SecurityRealmDescriptor {

    private final String name;
    private final RequestMatcher authenticationEndpointRequestMatcher;
    private final String firstStepName;
    private final SecurityRealmTokenCodec securityRealmTokenCodec;
    private final Duration fullyAuthenticatedTokenTtl;

    public SecurityRealmDescriptor(
        String name,
        RequestMatcher authenticationEndpointRequestMatcher,
        String firstStepName,
        SecurityRealmTokenCodec securityRealmTokenCodec,
        Duration fullyAuthenticatedTokenTtl
    ) {
        this.name = name;
        this.authenticationEndpointRequestMatcher = authenticationEndpointRequestMatcher;
        this.firstStepName = firstStepName;
        this.securityRealmTokenCodec = securityRealmTokenCodec;
        this.fullyAuthenticatedTokenTtl = fullyAuthenticatedTokenTtl;
    }

    public String getName() {
        return name;
    }

    public RequestMatcher getAuthenticationEndpointRequestMatcher() {
        return authenticationEndpointRequestMatcher;
    }

    public String getFirstStepName() {
        return firstStepName;
    }

    public SecurityRealmTokenCodec getSecurityRealmTokenCodec() {
        return securityRealmTokenCodec;
    }

    public Duration getFullyAuthenticatedTokenTtl() {
        return fullyAuthenticatedTokenTtl;
    }
}
