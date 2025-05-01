package net.coder966.spring.multisecurityrealms.reflection;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import net.coder966.spring.multisecurityrealms.converter.SecurityRealmTokenCodec;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Getter
@AllArgsConstructor
public class SecurityRealmDescriptor {

    private final String name;
    private final RequestMatcher authenticationEndpointRequestMatcher;
    private final String firstStepName;
    private final List<RequestMatcher> publicApisRequestMatchers;
    private final SecurityRealmTokenCodec securityRealmTokenCodec;
}
