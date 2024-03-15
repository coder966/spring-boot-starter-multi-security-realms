package net.coder966.spring.multisecurityrealms.reflection;

import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Getter
@AllArgsConstructor
public class SecurityRealmHandler {

    private final String name;
    private final RequestMatcher authenticationEndpointRequestMatcher;
    private final String firstStepName;
    private final List<RequestMatcher> publicApisRequestMatchers;
    private final Map<String, AuthenticationStepInvoker> authenticationStepInvokers;
}
