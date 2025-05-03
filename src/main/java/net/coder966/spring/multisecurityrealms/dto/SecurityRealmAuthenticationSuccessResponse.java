package net.coder966.spring.multisecurityrealms.dto;


import java.util.Set;

public class SecurityRealmAuthenticationSuccessResponse {

    public String realm;

    public String token;

    public String name;
    public Set<String> authorities;


    public String nextAuthenticationStep;
}
