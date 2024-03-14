package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.autoconfigure.SecurityRealmConfig;
import net.coder966.spring.multisecurityrealms.converter.AuthenticationTokenConverter;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAnonymousAuthentication;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

@Slf4j
public class SecurityRealmAuthenticationFilter {

    private final SecurityRealmConfig config;
    private final SecurityRealm realm;
    private final AuthenticationTokenConverter authenticationTokenConverter;

    // response headers
    private final String NEXT_STEP_RESPONSE_HEADER_NAME = "X-Next-Auth-Step";
    private final String ERROR_CODE_RESPONSE_HEADER_NAME = "X-Auth-Error-Code";

    public SecurityRealmAuthenticationFilter(SecurityRealmConfig config, SecurityRealm realm) {
        this.config = config;
        this.realm = realm;
        this.authenticationTokenConverter = new AuthenticationTokenConverter(config.getSigningSecret(), config.getTokenExpirationDuration());
    }

    private boolean matchesLogin(HttpServletRequest request) {
        return request.getMethod().equals("POST") && request.getRequestURI().equals(realm.getLoginUrl());
    }

    private boolean matchesPublicApi(HttpServletRequest request) {
        return realm.getPublicApisRequestMatchers().stream().anyMatch(requestMatcher -> requestMatcher.matches(request));
    }

    public boolean handle(HttpServletRequest request, HttpServletResponse response) {
        Authentication authenticationExtractedFromRequest = extractAuthenticationFromRequest(request);
        if(authenticationExtractedFromRequest != null){
            setAuthenticationInContext(authenticationExtractedFromRequest);
        }


        if(matchesLogin(request)){
            handleLogin(request, response);
            return true;
        }


        if(matchesPublicApi(request) && authenticationExtractedFromRequest == null){
            // don't use AnonymousAuthenticationToken because it will be rejected down via AuthorizationFilter
            setAuthenticationInContext(new SecurityRealmAnonymousAuthentication());
            // don't return, we need to continue the filter chain on order to reach the servlet controller
        }

        return false;
    }

    private void handleLogin(HttpServletRequest request, HttpServletResponse response) {
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

        SecurityRealmAuthentication currentRealmAuth = null;
        String step = null;
        if(currentAuth instanceof SecurityRealmAuthentication){
            currentRealmAuth = (SecurityRealmAuthentication) currentAuth;
            if(currentRealmAuth.getRealmName().equals(realm.getName())){
                step = currentRealmAuth.getNextAuthStep();
            }
        }

        try{
            SecurityRealmAuthentication resultAuth = realm.authenticate(request, step, currentRealmAuth);
            handleLoginAuthenticationResult(resultAuth, response);
        }catch(AuthenticationException e){
            response.setStatus(401);
            response.setHeader(ERROR_CODE_RESPONSE_HEADER_NAME, e.getMessage());
        }
    }

    @SneakyThrows
    private void handleLoginAuthenticationResult(SecurityRealmAuthentication resultAuth, HttpServletResponse response) {
        if(resultAuth == null){
            throw new IllegalStateException("You should not return a null SecurityRealmAuthentication. "
                + "To indicate authentication failure, throw exceptions of type AuthenticationException.");
        }

        resultAuth.setRealmName(realm.getName());

        if(resultAuth.getNextAuthStep() != null){
            response.setHeader(NEXT_STEP_RESPONSE_HEADER_NAME, resultAuth.getNextAuthStep());
        }

        response.setHeader("Content-Type", "text/plain;charset=UTF-8");

        String token = authenticationTokenConverter.createToken(resultAuth);
        response.getWriter().write(token);
    }

    private Authentication extractAuthenticationFromRequest(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");

        if(authorization != null){
            if(authorization.startsWith("Bearer ")){
                authorization = authorization.substring(6);
            }

            SecurityRealmAuthentication authentication = authenticationTokenConverter.verifyToken(authorization);
            if(authentication != null && authentication.getRealmName().equals(realm.getName())){
                return authentication;
            }
        }

        return null;
    }

    private void setAuthenticationInContext(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

}
