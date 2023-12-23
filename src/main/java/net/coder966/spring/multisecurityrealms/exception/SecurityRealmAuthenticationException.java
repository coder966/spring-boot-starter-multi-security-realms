package net.coder966.spring.multisecurityrealms.exception;

import org.springframework.security.core.AuthenticationException;

public class SecurityRealmAuthenticationException extends AuthenticationException {

    public SecurityRealmAuthenticationException(String errorCode) {
        super(errorCode);
    }
}
