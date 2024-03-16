package net.coder966.spring.multisecurityrealms.authentication;

import java.util.Collection;
import java.util.Set;
import java.util.UUID;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class SecurityRealmAnonymousAuthentication implements Authentication {

    @Getter
    private final String anonymousKey = UUID.randomUUID().toString();
    
    private final Set<GrantedAuthority> authorities = Set.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"));

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
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
        return "anonymousUser";
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return "anonymousUser";
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof SecurityRealmAnonymousAuthentication test){
            return (this.anonymousKey.equals(test.getAnonymousKey()));
        }
        return false;
    }

    @Override
    public int hashCode() {
        return anonymousKey.hashCode();
    }
}
