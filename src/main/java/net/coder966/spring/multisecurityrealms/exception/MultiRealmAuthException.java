package net.coder966.spring.multisecurityrealms.exception;

import org.springframework.security.core.AuthenticationException;

public class MultiRealmAuthException extends AuthenticationException {

    public MultiRealmAuthException(String errorCode) {
        super(errorCode);
    }
}
