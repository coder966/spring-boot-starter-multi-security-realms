package net.coder966.spring.multisecurityrealms.reflection;

import java.util.List;
import net.coder966.spring.multisecurityrealms.converter.SecurityRealmTokenCodec;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class SecurityRealmDescriptor {

    private final String name;
    private final RequestMatcher authenticationEndpointRequestMatcher;
    private final String firstStepName;
    private final List<RequestMatcher> publicApisRequestMatchers;
    private final SecurityRealmTokenCodec securityRealmTokenCodec;

    public SecurityRealmDescriptor(String name, RequestMatcher authenticationEndpointRequestMatcher, String firstStepName,
        List<RequestMatcher> publicApisRequestMatchers, SecurityRealmTokenCodec securityRealmTokenCodec) {
        this.name = name;
        this.authenticationEndpointRequestMatcher = authenticationEndpointRequestMatcher;
        this.firstStepName = firstStepName;
        this.publicApisRequestMatchers = publicApisRequestMatchers;
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

    public List<RequestMatcher> getPublicApisRequestMatchers() {
        return publicApisRequestMatchers;
    }

    public SecurityRealmTokenCodec getSecurityRealmTokenCodec() {
        return securityRealmTokenCodec;
    }
}
