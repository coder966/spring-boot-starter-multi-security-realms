package net.coder966.spring.multisecurityrealms.model;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SecurityRealmAuthenticationResponse {
    private String realm;
    private String token;
    private String nextAuthenticationStep;
    private String error;
}
