package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

public abstract class AbstractAuthenticationFilter {

    /**
     * @return true to stop the filter chain
     */
    public abstract boolean handle(HttpServletRequest request, HttpServletResponse response);

    protected void setAuthenticationInContext(Authentication authentication) {
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

}
