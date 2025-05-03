package net.coder966.spring.multisecurityrealms.dto;


import java.util.Set;

public class SecurityRealmAuthenticationResponse {

    public String realm;

    public String name;
    public Set<String> authorities;

    public String token;

    public String nextAuthenticationStep;
    public String error;
}
