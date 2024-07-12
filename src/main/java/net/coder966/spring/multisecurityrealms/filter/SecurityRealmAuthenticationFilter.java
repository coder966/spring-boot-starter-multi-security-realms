package net.coder966.spring.multisecurityrealms.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAnonymousAuthentication;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import net.coder966.spring.multisecurityrealms.reflection.AuthenticationStepInvoker;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmDescriptor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

@Slf4j
public class SecurityRealmAuthenticationFilter {

    private final SecurityRealmDescriptor descriptor;
    private final ObjectMapper objectMapper;

    public SecurityRealmAuthenticationFilter(
        SecurityRealmDescriptor descriptor,
        ObjectMapper objectMapper
    ) {
        this.descriptor = descriptor;
        this.objectMapper = objectMapper;
    }

    private boolean matchesLogin(HttpServletRequest request) {
        return request.getMethod().equals("POST") && descriptor.getAuthenticationEndpointRequestMatcher().matches(request);
    }

    private boolean matchesPublicApi(HttpServletRequest request) {
        return descriptor.getPublicApisRequestMatchers().stream().anyMatch(requestMatcher -> requestMatcher.matches(request));
    }

    public boolean handle(HttpServletRequest request, HttpServletResponse response) {
        SecurityRealmContext.setDescriptor(descriptor);

        SecurityRealmAuthentication auth = extractAuthenticationFromRequest(request);
        if(auth != null){
            setAuthenticationInContext(auth);
        }

        SecurityRealmContext.setCurrentStep(auth == null ? descriptor.getFirstStepName() : auth.getNextAuthenticationStep());


        if(matchesLogin(request)){
            handleLogin(request, response, auth);
            return true;
        }


        if(matchesPublicApi(request)){
            if(auth == null || !auth.isAuthenticated()){
                // don't use AnonymousAuthenticationToken because it will be rejected down via AuthorizationFilter
                setAuthenticationInContext(new SecurityRealmAnonymousAuthentication());
            }

            // don't return true; as we need to continue the filter chain on order to reach the servlet controller
            return false;
        }

        // anything else
        return false;
    }

    private void handleLogin(HttpServletRequest request, HttpServletResponse response, SecurityRealmAuthentication auth) {
        if(auth != null && auth.isAuthenticated()){
            SecurityRealmAuthentication resultAuth = new SecurityRealmAuthentication(auth.getName(), auth.getAuthorities());
            resultAuth.setError("Already fully authenticated");
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            writeAuthenticationResponse(resultAuth, response);
            return;
        }

        try{
            AuthenticationStepInvoker stepInvoker = descriptor.getAuthenticationStepInvokers().get(SecurityRealmContext.getCurrentStep());
            SecurityRealmAuthentication resultAuth = stepInvoker.invoke(request, response, auth);

            if(resultAuth == null){
                throw new IllegalStateException("You should not return a null SecurityRealmAuthentication. "
                    + "To indicate authentication failure, throw exceptions of type SecurityRealmAuthenticationException.");
            }

            writeAuthenticationResponse(resultAuth, response);
        }catch(SecurityRealmAuthenticationException e){
            SecurityRealmAuthentication resultAuth = new SecurityRealmAuthentication(
                auth == null ? null : auth.getName(),
                auth == null ? null : auth.getAuthorities(),
                auth == null ? SecurityRealmContext.getCurrentStep() : auth.getNextAuthenticationStep()
            );
            resultAuth.setError(e.getMessage());
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            writeAuthenticationResponse(resultAuth, response);
        }

    }

    private SecurityRealmAuthentication extractAuthenticationFromRequest(HttpServletRequest request) {
        String authorization = extractTokenFromRequest(request);

        if(authorization != null){
            SecurityRealmAuthentication authentication = descriptor.getAuthenticationTokenConverter().verifyToken(authorization);
            if(authentication != null && authentication.getRealm().equals(descriptor.getName())){
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
        if(doesContextHoldStrongerAuthentication(authentication)){
            return;
        }

        SecurityContext newContext = SecurityContextHolder.createEmptyContext();
        newContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(newContext);
    }

    private boolean doesContextHoldStrongerAuthentication(Authentication newAuth) {
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

        if(currentAuth == null){
            return false;
        }

        if(!currentAuth.isAuthenticated() && newAuth.isAuthenticated()){
            return false;
        }

        return true;
    }


    @SneakyThrows
    private void writeAuthenticationResponse(SecurityRealmAuthentication authentication, HttpServletResponse response) {
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(authentication));
        response.getWriter().close();
    }

}
