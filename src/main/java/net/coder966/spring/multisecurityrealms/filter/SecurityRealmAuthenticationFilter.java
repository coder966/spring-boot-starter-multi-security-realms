package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationAlreadyAuthenticatedException;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmDescriptor;
import org.springframework.context.ApplicationContext;
import org.springframework.web.servlet.HandlerExceptionResolver;

public class SecurityRealmAuthenticationFilter extends AbstractAuthenticationFilter {

    private final SecurityRealmDescriptor descriptor;
    private final HttpServlet httpServlet;
    private final Collection<HandlerExceptionResolver> exceptionResolvers;

    public SecurityRealmAuthenticationFilter(ApplicationContext context, SecurityRealmDescriptor descriptor) {
        this.descriptor = descriptor;
        this.httpServlet = context.getBean(HttpServlet.class);
        this.exceptionResolvers = context.getBeansOfType(HandlerExceptionResolver.class).values();
    }

    public boolean handle(HttpServletRequest request, HttpServletResponse response){
        SecurityRealmAuthentication auth = extractAuthenticationFromRequest(request);

        boolean isAuthenticationRequest = descriptor.getAuthenticationEndpointRequestMatcher().matches(request);
        boolean isSameRealm = isAuthenticationRequest || (auth != null && auth.getRealm().equals(descriptor.getName()));

        if(!isSameRealm){
            return false;
        }

        // populate SecurityRealmContext and SecurityContextHolder
        SecurityRealmContext.setDescriptor(descriptor);
        if(auth == null){
            SecurityRealmContext.setCurrentStep(descriptor.getFirstStepName());
        }else{
            setAuthenticationInContext(auth);
            SecurityRealmContext.setCurrentStep(auth.getNextAuthenticationStep());
        }

        if(isAuthenticationRequest){

            // if already fully authenticated
            if(auth != null && auth.isAuthenticated()){
                exceptionResolvers
                    .forEach(resolver -> resolver.resolveException(request, response, null, new SecurityRealmAuthenticationAlreadyAuthenticatedException()));
                return true;
            }

            // craft the request so that it can be routed to the appropriate step handler
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

            // dispatch
            try{
                httpServlet.service(wrapped, response);
            }catch(Exception e){
                throw new RuntimeException(e);
            }

            return true;

        }else{
            return false;
        }
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
