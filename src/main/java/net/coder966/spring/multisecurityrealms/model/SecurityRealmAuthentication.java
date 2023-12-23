package net.coder966.spring.multisecurityrealms.model;

import java.util.HashSet;
import java.util.Set;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Setter
@Getter
public class SecurityRealmAuthentication<T> implements Authentication {

    private T principal;
    private String name;
    private Set<SimpleGrantedAuthority> authorities;
    private boolean isAuthenticated;
    private String nextAuthStep;

    /**
     * USe this when the user is fully authenticated.
     */
    public SecurityRealmAuthentication(T principal, String name, Set<SimpleGrantedAuthority> authorities) {
        this.principal = principal;
        this.name = name;
        this.authorities = authorities == null ? new HashSet<>() : authorities;
        this.isAuthenticated = true;
        this.nextAuthStep = null;
    }

    /**
     * USe this when the user is not fully authenticated and needs to proceed to the another auth step.
     */
    public SecurityRealmAuthentication(T principal, String name, Set<SimpleGrantedAuthority> authorities, String nextAuthStep) {
        this.principal = principal;
        this.name = name;
        this.authorities = authorities == null ? new HashSet<>() : authorities;
        this.isAuthenticated = nextAuthStep == null;
        this.nextAuthStep = nextAuthStep;
    }

    @Override
    public Set<SimpleGrantedAuthority> getAuthorities() {
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
    public T getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.isAuthenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return name;
    }
}
