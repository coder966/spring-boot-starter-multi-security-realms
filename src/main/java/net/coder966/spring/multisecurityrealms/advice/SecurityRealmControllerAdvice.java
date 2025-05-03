package net.coder966.spring.multisecurityrealms.advice;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.util.Collections;
import java.util.stream.Collectors;
import net.coder966.spring.multisecurityrealms.annotation.AuthenticationStep;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import net.coder966.spring.multisecurityrealms.dto.SecurityRealmAuthenticationResponse;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationAlreadyAuthenticatedException;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

@Order(Ordered.HIGHEST_PRECEDENCE + 100) // + 100 to allow user some room to override this if they want
@ControllerAdvice
public class SecurityRealmControllerAdvice implements ResponseBodyAdvice<Object> {

    @ExceptionHandler(SecurityRealmAuthenticationException.class)
    public ResponseEntity<SecurityRealmAuthenticationResponse> handleAuthError(SecurityRealmAuthenticationException e) {
        SecurityRealmAuthentication currentAuth = (SecurityRealmAuthentication) SecurityContextHolder.getContext().getAuthentication();
        SecurityRealmAuthenticationResponse response = mapError(currentAuth, e);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(SecurityRealmAuthenticationAlreadyAuthenticatedException.class)
    public ResponseEntity<SecurityRealmAuthenticationResponse> handleAlreadyAuthenticated(SecurityRealmAuthenticationAlreadyAuthenticatedException e) {
        SecurityRealmAuthentication currentAuth = (SecurityRealmAuthentication) SecurityContextHolder.getContext().getAuthentication();
        SecurityRealmAuthenticationResponse response = mapSuccess(currentAuth);
        return ResponseEntity.ok(response);
    }

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        var isAuthenticationStep = returnType.hasMethodAnnotation(AuthenticationStep.class);
        var isReturningAuthentication = returnType.hasMethodAnnotation(AuthenticationStep.class);
        return isAuthenticationStep && isReturningAuthentication;
    }

    @Override
    public Object beforeBodyWrite(
        Object body, MethodParameter returnType,
        MediaType selectedContentType, Class<? extends HttpMessageConverter<?>> selectedConverterType,
        ServerHttpRequest request, ServerHttpResponse response
    ) {
        SecurityRealmAuthentication auth = (SecurityRealmAuthentication) body;
        return mapSuccess(auth);
    }

    private SecurityRealmAuthenticationResponse mapSuccess(@Nonnull SecurityRealmAuthentication auth) {
        SecurityRealmAuthenticationResponse response = new SecurityRealmAuthenticationResponse();

        response.realm = SecurityRealmContext.getDescriptor().getName();

        response.name = auth.getName();
        response.authorities = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());

        response.token = SecurityRealmContext.getDescriptor().getSecurityRealmTokenCodec().encode(auth);
        response.nextAuthenticationStep = auth.getNextAuthenticationStep();

        return response;
    }

    private SecurityRealmAuthenticationResponse mapError(@Nullable SecurityRealmAuthentication auth, @Nonnull SecurityRealmAuthenticationException e) {
        SecurityRealmAuthenticationResponse response = new SecurityRealmAuthenticationResponse();

        response.realm = SecurityRealmContext.getDescriptor().getName();

        if(auth == null){
            response.name = null;
            response.authorities = Collections.emptySet();
            response.token = null;
        }else{
            response.name = auth.getName();
            response.authorities = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
            response.token = SecurityRealmContext.getDescriptor().getSecurityRealmTokenCodec().encode(auth);
        }

        response.nextAuthenticationStep = SecurityRealmContext.getCurrentStep();
        response.error = e.getMessage();

        return response;
    }
}
