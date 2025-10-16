package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAnonymousAuthentication;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationAlreadyAuthenticatedException;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmDescriptor;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.HandlerExceptionResolver;

public class SecurityRealmAuthenticationFilter {

    private final SecurityRealmDescriptor descriptor;
    private final HttpServlet httpServlet;
    private final Collection<HandlerExceptionResolver> exceptionResolvers;

    public SecurityRealmAuthenticationFilter(ApplicationContext context, SecurityRealmDescriptor descriptor) {
        this.descriptor = descriptor;
        this.httpServlet = context.getBean(HttpServlet.class);
        this.exceptionResolvers = context.getBeansOfType(HandlerExceptionResolver.class).values();
    }

    private boolean matchesLogin(HttpServletRequest request) {
        return request.getMethod().equals("POST") && descriptor.getAuthenticationEndpointRequestMatcher().matches(request);
    }

    private boolean matchesPublicApi(HttpServletRequest request) {
        return descriptor.getPublicApisRequestMatchers().stream().anyMatch(requestMatcher -> requestMatcher.matches(request));
    }

    public boolean handle(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
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

        // cleanup
        SecurityRealmContext.setDescriptor(null);
        SecurityRealmContext.setCurrentStep(null);


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

    private void handleLogin(HttpServletRequest request, HttpServletResponse response, SecurityRealmAuthentication auth) throws ServletException, IOException {
        if(auth != null && auth.isAuthenticated()){
            exceptionResolvers
                .forEach(resolver -> resolver.resolveException(request, response, null, new SecurityRealmAuthenticationAlreadyAuthenticatedException()));
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

        httpServlet.service(wrapped, response);
    }

    private SecurityRealmAuthentication extractAuthenticationFromRequest(HttpServletRequest request) {
        String authorization = extractTokenFromRequest(request);

        if(authorization != null){
            SecurityRealmAuthentication authentication = descriptor.getSecurityRealmTokenCodec().decode(authorization);
            if(authentication != null && authentication.getRealm().equals(descriptor.getName())){
                return authentication;
            }
        }

        return null;
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String authorization;

        if(isWebsocketUpgradeRequest(request)){
            // if the request is a websocket upgrade, we support passing the token in Authorization param or token param (case-sensitive)
            authorization = request.getParameter("Authorization");
            if(authorization == null){
                authorization = request.getParameter("token");
            }
        }else{
            authorization = request.getHeader("Authorization");
        }

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

    private boolean isWebsocketUpgradeRequest(HttpServletRequest request){
        String connectionHeader = request.getHeader("Connection");
        if(connectionHeader == null || !connectionHeader.equalsIgnoreCase("Upgrade")){
            return false;
        }
        String upgradeHeader = request.getHeader("Upgrade");
        if(upgradeHeader == null || !upgradeHeader.equalsIgnoreCase("websocket")){
            return false;
        }
        return true;
    }

}
