package net.coder966.spring.multisecurityrealms.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.autoconfigure.SecurityRealmConfig;
import net.coder966.spring.multisecurityrealms.converter.AuthenticationTokenConverter;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAnonymousAuthentication;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthenticationResponse;
import net.coder966.spring.multisecurityrealms.reflection.AuthenticationStepInvoker;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmHandler;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;

@Slf4j
public class SecurityRealmAuthenticationFilter {

    private final SecurityRealmConfig config;
    private final SecurityRealmHandler handler;
    private final ObjectMapper objectMapper;
    private final AuthenticationTokenConverter authenticationTokenConverter;

    public SecurityRealmAuthenticationFilter(SecurityRealmConfig config, SecurityRealmHandler handler) {
        this.config = config;
        this.handler = handler;
        this.objectMapper = new ObjectMapper();
        this.authenticationTokenConverter = new AuthenticationTokenConverter(config.getSigningSecret(), config.getTokenExpirationDuration());
    }

    private boolean matchesLogin(HttpServletRequest request) {
        return request.getMethod().equals("POST") && handler.getAuthenticationEndpointRequestMatcher().matches(request);
    }

    private boolean matchesPublicApi(HttpServletRequest request) {
        return handler.getPublicApisRequestMatchers().stream().anyMatch(requestMatcher -> requestMatcher.matches(request));
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
        String step = authenticationExtractedFromRequest == null ? handler.getFirstStepName() : authenticationExtractedFromRequest.getNextAuthenticationStep();
        SecurityRealmAuthenticationResponse responseBody = new SecurityRealmAuthenticationResponse();
        responseBody.setRealm(handler.getName());

        try{
            AuthenticationStepInvoker stepInvoker = handler.getAuthenticationStepInvokers().get(step);
            SecurityRealmAuthentication resultAuth = stepInvoker.invoke(request, response, authenticationExtractedFromRequest);

            if(resultAuth == null){
                throw new IllegalStateException("You should not return a null SecurityRealmAuthentication. "
                    + "To indicate authentication failure, throw exceptions of type AuthenticationException.");
            }

            resultAuth.setRealmName(handler.getName());
            responseBody.setToken(authenticationTokenConverter.createToken(resultAuth));
            responseBody.setNextAuthenticationStep(resultAuth.getNextAuthenticationStep());
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
            if(authentication != null && authentication.getRealmName().equals(handler.getName())){
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
