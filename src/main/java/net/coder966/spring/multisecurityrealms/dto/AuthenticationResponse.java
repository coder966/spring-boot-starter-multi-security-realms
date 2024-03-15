package net.coder966.spring.multisecurityrealms.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthenticationResponse {
    private String realm;
    private String token;
    private String nextAuthenticationStep;
    private String error;
}
