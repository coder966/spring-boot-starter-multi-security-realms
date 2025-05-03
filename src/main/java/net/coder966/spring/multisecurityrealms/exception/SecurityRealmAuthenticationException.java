package net.coder966.spring.multisecurityrealms.exception;

import org.springframework.security.core.AuthenticationException;

public class SecurityRealmAuthenticationException extends AuthenticationException {

    /**
     * Human-readable error message.
     */
    private final String errorDescription;

    public SecurityRealmAuthenticationException(String errorCode) {
        super(errorCode);
        this.errorDescription = null;
    }

    public SecurityRealmAuthenticationException(String errorCode, String errorDescription) {
        super(errorCode);
        this.errorDescription = errorDescription;
    }

    public String getErrorDescription() {
        return errorDescription;
    }
}
