package net.coder966.spring.multisecurityrealms.exception;

import org.springframework.security.core.AuthenticationException;

public class SecurityRealmAuthException extends AuthenticationException {

    public SecurityRealmAuthException(String errorCode) {
        super(errorCode);
    }
}
