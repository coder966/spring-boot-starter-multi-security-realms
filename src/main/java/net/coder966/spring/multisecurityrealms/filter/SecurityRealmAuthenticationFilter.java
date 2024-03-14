package net.coder966.spring.multisecurityrealms.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.autoconfigure.SecurityRealmConfig;
import net.coder966.spring.multisecurityrealms.converter.AuthenticationTokenConverter;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAnonymousAuthentication;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthenticationResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

@Slf4j
public class SecurityRealmAuthenticationFilter {

    private final SecurityRealmConfig config;
    private final SecurityRealm realm;
    private final ObjectMapper objectMapper;
    private final AuthenticationTokenConverter authenticationTokenConverter;

    public SecurityRealmAuthenticationFilter(SecurityRealmConfig config, SecurityRealm realm) {
        this.config = config;
        this.realm = realm;
        this.objectMapper = new ObjectMapper();
        this.authenticationTokenConverter = new AuthenticationTokenConverter(config.getSigningSecret(), config.getTokenExpirationDuration());
    }

    private boolean matchesLogin(HttpServletRequest request) {
        return request.getMethod().equals("POST") && request.getRequestURI().equals(realm.getLoginUrl());
    }

    private boolean matchesPublicApi(HttpServletRequest request) {
        return realm.getPublicApisRequestMatchers().stream().anyMatch(requestMatcher -> requestMatcher.matches(request));
    }

    public boolean handle(HttpServletRequest request, HttpServletResponse response) {
        SecurityRealmAuthentication authenticationExtractedFromRequest = extractAuthenticationFromRequest(request);
        if(authenticationExtractedFromRequest != null){
            setAuthenticationInContext(authenticationExtractedFromRequest);
        }


        if(matchesLogin(request)){
            handleLogin(request, response, authenticationExtractedFromRequest);
            return true;
        }


        if(matchesPublicApi(request) && authenticationExtractedFromRequest == null){
            // don't use AnonymousAuthenticationToken because it will be rejected down via AuthorizationFilter
            setAuthenticationInContext(new SecurityRealmAnonymousAuthentication());
            // don't return, we need to continue the filter chain on order to reach the servlet controller
        }

        return false;
    }

    @SneakyThrows
    private void handleLogin(HttpServletRequest request, HttpServletResponse response, SecurityRealmAuthentication authenticationExtractedFromRequest) {
        String step = authenticationExtractedFromRequest == null ? null : authenticationExtractedFromRequest.getNextAuthStep();
        SecurityRealmAuthenticationResponse responseBody = new SecurityRealmAuthenticationResponse();
        responseBody.setRealm(realm.getName());

        try{
            SecurityRealmAuthentication resultAuth = realm.authenticate(
                request,
                step,
                authenticationExtractedFromRequest
            );

            if(resultAuth == null){
                throw new IllegalStateException("You should not return a null SecurityRealmAuthentication. "
                    + "To indicate authentication failure, throw exceptions of type AuthenticationException.");
            }

            resultAuth.setRealmName(realm.getName());
            responseBody.setToken(authenticationTokenConverter.createToken(resultAuth));
            responseBody.setNextAuthenticationStep(resultAuth.getNextAuthStep());
        }catch(AuthenticationException e){
            responseBody.setToken(extractTokenFromRequest(request));
            responseBody.setNextAuthenticationStep(step);
            responseBody.setError(e.getMessage());
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
        }

        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(responseBody));
        response.getWriter().close();
    }

    private SecurityRealmAuthentication extractAuthenticationFromRequest(HttpServletRequest request) {
        String authorization = extractTokenFromRequest(request);

        if(authorization != null){
            SecurityRealmAuthentication authentication = authenticationTokenConverter.verifyToken(authorization);
            if(authentication != null && authentication.getRealmName().equals(realm.getName())){
                return authentication;
            }
        }

        return null;
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");

        if(authorization != null){
            if(authorization.startsWith("Bearer ")){
                authorization = authorization.substring(6);
            }
            return authorization;
        }

        return null;
    }

    private void setAuthenticationInContext(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

}
