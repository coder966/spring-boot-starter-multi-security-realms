package net.coder966.spring.multisecurityrealms.advice;

import jakarta.annotation.Nonnull;
import java.util.stream.Collectors;
import net.coder966.spring.multisecurityrealms.annotation.AuthenticationStep;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import net.coder966.spring.multisecurityrealms.dto.SecurityRealmAuthenticationErrorResponse;
import net.coder966.spring.multisecurityrealms.dto.SecurityRealmAuthenticationSuccessResponse;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationAlreadyAuthenticatedException;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
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
    public ResponseEntity<SecurityRealmAuthenticationErrorResponse> handleAuthError(SecurityRealmAuthenticationException e) {
        return ResponseEntity.status(400).body(mapError(e));
    }

    @ExceptionHandler(SecurityRealmAuthenticationAlreadyAuthenticatedException.class)
    public ResponseEntity<SecurityRealmAuthenticationSuccessResponse> handleAlreadyAuthenticated(SecurityRealmAuthenticationAlreadyAuthenticatedException e) {
        SecurityRealmAuthentication currentAuth = (SecurityRealmAuthentication) SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(mapSuccess(currentAuth));
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

    private SecurityRealmAuthenticationSuccessResponse mapSuccess(@Nonnull SecurityRealmAuthentication auth) {
        var realmDescriptor = SecurityRealmContext.getDescriptor();
        var response = new SecurityRealmAuthenticationSuccessResponse();

        response.realm = realmDescriptor.getName();

        response.name = auth.getName();
        response.authorities = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());

        response.token = realmDescriptor.getSecurityRealmTokenCodec().encode(auth);
        response.tokenType = "Bearer";
        response.expiresInSeconds = realmDescriptor.getSecurityRealmTokenCodec().getTtl().toSeconds();

        response.nextAuthenticationStep = auth.getNextAuthenticationStep();

        response.extras = auth.getExtras();

        return response;
    }

    private SecurityRealmAuthenticationErrorResponse mapError(@Nonnull SecurityRealmAuthenticationException e) {
        var response = new SecurityRealmAuthenticationErrorResponse();

        response.error = e.getMessage();

        return response;
    }
}
