package net.coder966.spring.multisecurityrealms.authentication;

import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class SecurityRealmAuthentication implements Authentication {

    private String realm;

    private final String name;
    private final Set<? extends GrantedAuthority> authorities;

    private final String nextAuthenticationStep;
    private final Duration tokenTtl;

    private final Map<String, Object> extras = new HashMap<>();


    /**
     * Use this when the user is fully authenticated.
     */
    public SecurityRealmAuthentication(String name, Set<? extends GrantedAuthority> authorities) {
        this(name, authorities, null, null);
    }

    /**
     * Use this when the user is not fully authenticated and needs to proceed to the another auth step.
     */
    public SecurityRealmAuthentication(String name, Set<? extends GrantedAuthority> authorities, String nextAuthenticationStep, Duration tokenTtl) {
        if(name == null || name.trim().length() != name.length() || name.isBlank()){
            throw new IllegalArgumentException("You must provide the username");
        }

        if(nextAuthenticationStep != null && tokenTtl == null){
            throw new IllegalArgumentException("Token TTL must be provided when nextAuthenticationStep is provided");
        }

        this.name = name;
        this.authorities = authorities == null ? new HashSet<>() : authorities;

        this.nextAuthenticationStep = nextAuthenticationStep;
        this.tokenTtl = tokenTtl;

        this.realm = SecurityRealmContext.getDescriptor() == null ? null : SecurityRealmContext.getDescriptor().getName();
    }

    /**
     * Add extra key-value information to the authentication response. It will be available in the response under "extras" field.
     */
    public SecurityRealmAuthentication addExtra(String key, Object value) {
        extras.put(key, value);
        return this;
    }

    public String getRealm() {
        return realm;
    }

    public String getNextAuthenticationStep() {
        return nextAuthenticationStep;
    }

    public Duration getTokenTtl() {
        return tokenTtl;
    }

    public Map<String, Object> getExtras() {
        return extras;
    }

    @Override
    public Set<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return realm + ":" + name;
    }

    @Override
    public boolean isAuthenticated() {
        return nextAuthenticationStep == null;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        throw new UnsupportedOperationException("SecurityRealmAuthentication does not support setAuthenticated(boolean)");
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof SecurityRealmAuthentication test){
            return (this.getPrincipal().equals(test.getPrincipal()));
        }
        return false;
    }

    @Override
    public int hashCode() {
        return this.getPrincipal().hashCode();
    }

    /**
     * this is used for internal use only
     */
    public void _UNSAFE_overrideRealm(String realm) {
        this.realm = realm;
    }
}
