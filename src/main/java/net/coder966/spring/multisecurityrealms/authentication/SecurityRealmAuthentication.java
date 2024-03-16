package net.coder966.spring.multisecurityrealms.authentication;

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
    private Set<? extends GrantedAuthority> authorities;
    private boolean isAuthenticated;
    private String nextAuthenticationStep;

    /**
     * USe this when the user is fully authenticated.
     */
    public SecurityRealmAuthentication(String name, Set<? extends GrantedAuthority> authorities) {
        this.name = name;
        this.authorities = authorities == null ? new HashSet<>() : authorities;
        this.isAuthenticated = true;
        this.nextAuthenticationStep = null;
    }

    /**
     * USe this when the user is not fully authenticated and needs to proceed to the another auth step.
     */
    public SecurityRealmAuthentication(String name, Set<? extends GrantedAuthority> authorities, String nextAuthenticationStep) {
        this.name = name;
        this.authorities = authorities == null ? new HashSet<>() : authorities;
        this.isAuthenticated = nextAuthenticationStep == null;
        this.nextAuthenticationStep = nextAuthenticationStep;
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
