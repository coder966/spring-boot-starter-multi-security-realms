package net.coder966.spring.multisecurityrealms.dto;

import java.util.Set;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

@Setter
@Getter
public class AuthenticationResponse {
    private String realm;
    private String name;
    private String token;
    private String nextAuthenticationStep;
    private Set<? extends GrantedAuthority> authorities;
    private String error;
}
