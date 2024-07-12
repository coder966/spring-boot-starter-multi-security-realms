package net.coder966.spring.multisecurityrealms.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAnonymousAuthentication;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmDescriptor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.support.WebApplicationContextUtils;

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

    @SneakyThrows
    private void handleLogin(HttpServletRequest request, HttpServletResponse response, SecurityRealmAuthentication auth) {
        if(auth != null && auth.isAuthenticated()){
            SecurityRealmAuthentication resultAuth = new SecurityRealmAuthentication(auth.getName(), auth.getAuthorities());
            resultAuth.setError("Already fully authenticated");
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            writeAuthenticationResponse(resultAuth, response);
            return;
        }


        HttpServletRequestWrapper wrapped = new HttpServletRequestWrapper(request) {
            @Override
            public String getParameter(String name) {
                return super.getParameter(name);
            }

            @Override
            public Map<String, String[]> getParameterMap() {
                // DON'T copy old params, or at lease copy old except the ones that start with "AuthenticationStep-"
                // not to allow the client to jump to incorrect/future step forcefully.
                Map<String, String[]> params = new HashMap<>();
                params.put("AuthenticationStep-" + SecurityRealmContext.getCurrentStep(), new String[]{UUID.randomUUID().toString()});
                return params;
            }
        };

        WebApplicationContextUtils
            .findWebApplicationContext(request.getServletContext())
            .getBean(HttpServlet.class)
            .service(wrapped, response);
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
