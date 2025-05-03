package net.coder966.spring.multisecurityrealms.authentication;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.HashSet;
import java.util.Set;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

@JsonIgnoreProperties({"authenticated", "credentials", "details", "principal"})
public class SecurityRealmAuthentication implements Authentication {

    private String realm;

    private final String name;
    private final Set<? extends GrantedAuthority> authorities;

    private final String nextAuthenticationStep;
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
        this.nextAuthenticationStep = nextAuthenticationStep;
        this.realm = SecurityRealmContext.getDescriptor() == null ? null : SecurityRealmContext.getDescriptor().getName();
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getNextAuthenticationStep() {
        return nextAuthenticationStep;
    }

    /**
     * to appear in the JSON response
     */
    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
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
     * to appear in the JSON response
     */
    public String getToken() {
        if(SecurityRealmContext.getDescriptor() == null){
            return null;
        }
        return SecurityRealmContext.getDescriptor().getSecurityRealmTokenCodec().encode(this);
    }
}
