package net.coder966.spring.multisecurityrealms.model;

import java.util.Collection;
import java.util.Collections;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class SecurityRealmAnonymousAuth implements Authentication {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptySet();
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
        return true;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return null;
    }
}
