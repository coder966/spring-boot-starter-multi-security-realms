package net.coder966.spring.multisecurityrealms.advice;

import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationAlreadyAuthenticatedException;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@Order(Ordered.HIGHEST_PRECEDENCE + 100) // + 100 to allow user some room to override this if they want
@ControllerAdvice
public class SecurityRealmControllerAdvice {

    @ExceptionHandler(SecurityRealmAuthenticationException.class)
    public ResponseEntity<SecurityRealmAuthentication> handleAuthError(SecurityRealmAuthenticationException e) {
        SecurityRealmAuthentication currentAuth = (SecurityRealmAuthentication) SecurityContextHolder.getContext().getAuthentication();
        SecurityRealmAuthentication resultAuth = new SecurityRealmAuthentication(
            currentAuth == null ? null : currentAuth.getName(),
            currentAuth == null ? null : currentAuth.getAuthorities(),
            currentAuth == null ? SecurityRealmContext.getCurrentStep() : currentAuth.getNextAuthenticationStep()
        );
        resultAuth.setError(e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(resultAuth);
    }

    @ExceptionHandler(SecurityRealmAuthenticationAlreadyAuthenticatedException.class)
    public ResponseEntity<SecurityRealmAuthentication> handleAlreadyAuthenticated(SecurityRealmAuthenticationAlreadyAuthenticatedException e) {
        SecurityRealmAuthentication currentAuth = (SecurityRealmAuthentication) SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(currentAuth);
    }
}
