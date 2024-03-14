package net.coder966.spring.multisecurityrealms.model;

import java.util.HashSet;
import java.util.Set;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

@Setter
@Getter
public class SecurityRealmAuthentication implements Authentication {
    private String realmName;
    private String name;
    private Set<GrantedAuthority> authorities;
    private boolean isAuthenticated;
    private String nextAuthStep;

    /**
     * USe this when the user is fully authenticated.
     */
    public SecurityRealmAuthentication(String name, Set<GrantedAuthority> authorities) {
        this.name = name;
        this.authorities = authorities == null ? new HashSet<>() : authorities;
        this.isAuthenticated = true;
        this.nextAuthStep = null;
    }

    /**
     * USe this when the user is not fully authenticated and needs to proceed to the another auth step.
     */
    public SecurityRealmAuthentication(String name, Set<GrantedAuthority> authorities, String nextAuthStep) {
        this.name = name;
        this.authorities = authorities == null ? new HashSet<>() : authorities;
        this.isAuthenticated = nextAuthStep == null;
        this.nextAuthStep = nextAuthStep;
    }

    @Override
    public Set<GrantedAuthority> getAuthorities() {
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
        return null;
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
