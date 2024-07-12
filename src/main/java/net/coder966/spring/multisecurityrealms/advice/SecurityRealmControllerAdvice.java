package net.coder966.spring.multisecurityrealms.advice;

import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@Slf4j
@ControllerAdvice
public class SecurityRealmControllerAdvice {

    @ExceptionHandler(SecurityRealmAuthenticationException.class)
    public ResponseEntity<SecurityRealmAuthentication> defaultSecurityRealmAuthenticationExceptionHandler(SecurityRealmAuthenticationException e) {
        SecurityRealmAuthentication currentAuth = (SecurityRealmAuthentication) SecurityContextHolder.getContext().getAuthentication();
        SecurityRealmAuthentication resultAuth = new SecurityRealmAuthentication(
            currentAuth == null ? null : currentAuth.getName(),
            currentAuth == null ? null : currentAuth.getAuthorities(),
            currentAuth == null ? SecurityRealmContext.getCurrentStep() : currentAuth.getNextAuthenticationStep()
        );
        resultAuth.setError(e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(resultAuth);
    }
}
