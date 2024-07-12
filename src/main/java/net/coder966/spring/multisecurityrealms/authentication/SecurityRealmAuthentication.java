package net.coder966.spring.multisecurityrealms.authentication;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.HashSet;
import java.util.Set;
import lombok.Getter;
import lombok.Setter;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

@Getter
@JsonIgnoreProperties({"authenticated", "credentials", "details", "principal"})
public class SecurityRealmAuthentication implements Authentication {

    private boolean isAuthenticated;

    private final String name;
    private final Set<? extends GrantedAuthority> authorities;
    private final String nextAuthenticationStep;

    @Setter
    private String error;


    /**
     * Use this when the user is fully authenticated.
     */
    public SecurityRealmAuthentication(String name, Set<? extends GrantedAuthority> authorities) {
        this(name, authorities, null);
    }

    /**
     * Use this when the user is not fully authenticated and needs to proceed to the another auth step.
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
        return getRealm() + ":" + name;
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

    public String getRealm() {
        return SecurityRealmContext.getDescriptor().getName();
    }

    public String getToken() {
        return SecurityRealmContext.getDescriptor().getAuthenticationTokenConverter().createToken(this);
    }
}
