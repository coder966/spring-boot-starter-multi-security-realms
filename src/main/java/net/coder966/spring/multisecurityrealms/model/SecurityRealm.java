package net.coder966.spring.multisecurityrealms.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import net.coder966.spring.multisecurityrealms.provider.SecurityRealmAuthProvider;
import net.coder966.spring.multisecurityrealms.provider.SecurityRealmFirstStepAuthProvider;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Getter
public class SecurityRealm<T> {

    private final String rolePrefix;
    private final String loginUrl;
    private final String logoutUrl;
    private SecurityRealmFirstStepAuthProvider<T> firstStepAuthProvider;
    private final Map<String, SecurityRealmAuthProvider<T>> authSteps;
    private final List<RequestMatcher> publicApisRequestMatchers = new ArrayList<>();

    public SecurityRealm(String rolePrefix, String loginUrl, String logoutUrl) {
        if(rolePrefix == null || rolePrefix.length() < 3 || rolePrefix.trim().length() != rolePrefix.length()){
            throw new IllegalArgumentException("Invalid rolePrefix: " + rolePrefix);
        }

        if(loginUrl == null || loginUrl.trim().length() != loginUrl.length()){
            throw new IllegalArgumentException("Invalid loginUrl: " + loginUrl);
        }

        if(logoutUrl == null || logoutUrl.trim().length() != logoutUrl.length()){
            throw new IllegalArgumentException("Invalid logoutUrl: " + logoutUrl);
        }

        if(logoutUrl.equals(loginUrl)){
            throw new IllegalArgumentException("logoutUrl cannot be the same as loginUrl");
        }

        this.rolePrefix = rolePrefix;
        this.loginUrl = loginUrl;
        this.logoutUrl = logoutUrl;
        this.authSteps = new HashMap<>();
    }

    public SecurityRealm<T> setFirstAuthStep(SecurityRealmFirstStepAuthProvider<T> authenticationProvider) {
        firstStepAuthProvider = authenticationProvider;
        return this;
    }

    /**
     * For multiple steps authentication, use this method to add a step.
     *
     * @param name                    The step name, must be unique for this realm.
     * @param authenticationProvider, the auth provider.
     */
    public SecurityRealm<T> addAuthStep(String name, SecurityRealmAuthProvider<T> authenticationProvider) {
        if(name == null || name.length() < 3 || name.trim().length() != name.length()){
            throw new IllegalArgumentException("Invalid auth step name: " + name);
        }

        if(authSteps.containsKey(name)){
            throw new IllegalArgumentException("Auth step already registered. Provided name: " + name);
        }

        authSteps.put(name, authenticationProvider);
        return this;
    }

    public SecurityRealm<T> publicApi(RequestMatcher requestMatcher) {
        publicApisRequestMatchers.add(requestMatcher);
        return this;
    }

}
