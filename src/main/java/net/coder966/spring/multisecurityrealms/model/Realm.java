package net.coder966.spring.multisecurityrealms.model;

import java.util.HashMap;
import java.util.Map;
import lombok.Getter;
import net.coder966.spring.multisecurityrealms.filter.SecurityRealmAuthFilter;
import net.coder966.spring.multisecurityrealms.provider.MultiRealmAuthProvider;
import net.coder966.spring.multisecurityrealms.provider.MultiRealmFirstStepAuthProvider;

@Getter
public class Realm<T> {

    private final String rolePrefix;
    private final String loginUrl;
    private final String logoutUrl;
    private MultiRealmFirstStepAuthProvider<T> firstStepAuthProvider;
    private final Map<String, MultiRealmAuthProvider<T>> authSteps;
    private SecurityRealmAuthFilter<T> filter;

    public Realm(String rolePrefix, String loginUrl, String logoutUrl) {
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

    public Realm<T> setFirstAuthStep(MultiRealmFirstStepAuthProvider<T> authenticationProvider) {
        firstStepAuthProvider = authenticationProvider;
        return this;
    }

    /**
     * For multiple steps authentication, use this method to add a step.
     *
     * @param name                    The step name, must be unique for this realm.
     * @param authenticationProvider, the auth provider.
     */
    public Realm<T> addAuthStep(String name, MultiRealmAuthProvider<T> authenticationProvider) {
        if(name == null || name.length() < 3 || name.trim().length() != name.length()){
            throw new IllegalArgumentException("Invalid auth step name: " + name);
        }

        if(authSteps.containsKey(name)){
            throw new IllegalArgumentException("Auth step already registered. Provided name: " + name);
        }

        authSteps.put(name, authenticationProvider);
        return this;
    }

    public SecurityRealmAuthFilter<T> getFilter() {
        if(filter == null){
            filter = new SecurityRealmAuthFilter<>(this);
        }
        return filter;
    }
}
