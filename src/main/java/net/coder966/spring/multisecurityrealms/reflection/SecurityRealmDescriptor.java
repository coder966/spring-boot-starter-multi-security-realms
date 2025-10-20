package net.coder966.spring.multisecurityrealms.reflection;

import net.coder966.spring.multisecurityrealms.converter.SecurityRealmTokenCodec;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class SecurityRealmDescriptor {

    private final String name;
    private final RequestMatcher authenticationEndpointRequestMatcher;
    private final String firstStepName;
    private final SecurityRealmTokenCodec securityRealmTokenCodec;

    public SecurityRealmDescriptor(
        String name,
        RequestMatcher authenticationEndpointRequestMatcher,
        String firstStepName,
        SecurityRealmTokenCodec securityRealmTokenCodec
    ) {
        this.name = name;
        this.authenticationEndpointRequestMatcher = authenticationEndpointRequestMatcher;
        this.firstStepName = firstStepName;
        this.securityRealmTokenCodec = securityRealmTokenCodec;
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
}
