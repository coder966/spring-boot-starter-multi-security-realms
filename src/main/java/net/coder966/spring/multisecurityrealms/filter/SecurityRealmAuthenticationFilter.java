package net.coder966.spring.multisecurityrealms.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAnonymousAuthentication;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.converter.AuthenticationTokenConverter;
import net.coder966.spring.multisecurityrealms.dto.AuthenticationResponse;
import net.coder966.spring.multisecurityrealms.reflection.AuthenticationStepInvoker;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmDescriptor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

@Slf4j
public class SecurityRealmAuthenticationFilter {

    private final SecurityRealmDescriptor descriptor;
    private final ObjectMapper objectMapper;
    private final AuthenticationTokenConverter authenticationTokenConverter;

    public SecurityRealmAuthenticationFilter(
        SecurityRealmDescriptor descriptor,
        AuthenticationTokenConverter authenticationTokenConverter,
        ObjectMapper objectMapper
    ) {
        this.descriptor = descriptor;
        this.objectMapper = objectMapper;
        this.authenticationTokenConverter = authenticationTokenConverter;
    }

    private boolean matchesLogin(HttpServletRequest request) {
        return request.getMethod().equals("POST") && descriptor.getAuthenticationEndpointRequestMatcher().matches(request);
    }

    private boolean matchesPublicApi(HttpServletRequest request) {
        return descriptor.getPublicApisRequestMatchers().stream().anyMatch(requestMatcher -> requestMatcher.matches(request));
    }

    public boolean handle(HttpServletRequest request, HttpServletResponse response) {
        SecurityRealmAuthentication auth = extractAuthenticationFromRequest(request);
        if(auth != null){
            setAuthenticationInContext(auth);
        }


        if(matchesLogin(request)){
            handleLogin(request, response, auth);
            return true;
        }


        if(matchesPublicApi(request) && auth == null){
            // don't use AnonymousAuthenticationToken because it will be rejected down via AuthorizationFilter
            setAuthenticationInContext(new SecurityRealmAnonymousAuthentication());
            // don't return, we need to continue the filter chain on order to reach the servlet controller
        }

        return false;
    }

    private void handleLogin(HttpServletRequest request, HttpServletResponse response, SecurityRealmAuthentication auth) {
        AuthenticationResponse responseBody = new AuthenticationResponse();
        responseBody.setRealm(descriptor.getName());

        if(auth != null && auth.isAuthenticated()){
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            responseBody.setError("Already fully authenticated");
            writeAuthenticationResponse(responseBody, response);
            return;
        }
        String step = auth == null ? descriptor.getFirstStepName() : auth.getNextAuthenticationStep();

        try{
            AuthenticationStepInvoker stepInvoker = descriptor.getAuthenticationStepInvokers().get(step);
            SecurityRealmAuthentication resultAuth = stepInvoker.invoke(request, response, auth);

            if(resultAuth == null){
                throw new IllegalStateException("You should not return a null SecurityRealmAuthentication. "
                    + "To indicate authentication failure, throw exceptions of type AuthenticationException.");
            }

            resultAuth.setRealmName(descriptor.getName());
            responseBody.setToken(authenticationTokenConverter.createToken(resultAuth));
            responseBody.setNextAuthenticationStep(resultAuth.getNextAuthenticationStep());
        }catch(AuthenticationException e){
            responseBody.setToken(extractTokenFromRequest(request));
            responseBody.setNextAuthenticationStep(step);
            responseBody.setError(e.getMessage());
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
        }

        writeAuthenticationResponse(responseBody, response);
    }

    private SecurityRealmAuthentication extractAuthenticationFromRequest(HttpServletRequest request) {
        String authorization = extractTokenFromRequest(request);

        if(authorization != null){
            SecurityRealmAuthentication authentication = authenticationTokenConverter.verifyToken(authorization);
            if(authentication != null && authentication.getRealmName().equals(descriptor.getName())){
                return authentication;
            }
        }

        return null;
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");

        if(authorization != null){
            if(authorization.toUpperCase().startsWith("BEARER ")){
                authorization = authorization.substring(7);
            }
            return authorization.trim();
        }

        return null;
    }

    private void setAuthenticationInContext(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @SneakyThrows
    private void writeAuthenticationResponse(AuthenticationResponse responseBody, HttpServletResponse response) {
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(responseBody));
        response.getWriter().close();
    }

}
