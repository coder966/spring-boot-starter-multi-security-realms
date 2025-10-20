package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAnonymousAuthentication;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class AnonymousAccessAuthenticationFilter extends AbstractAuthenticationFilter {

    private final List<RequestMatcher> requestMatchers;

    public AnonymousAccessAuthenticationFilter(List<RequestMatcher> requestMatchers) {
        this.requestMatchers = requestMatchers;
    }

    public boolean handle(HttpServletRequest request, HttpServletResponse response) {
        for(RequestMatcher matcher : requestMatchers){
            if(matcher.matches(request)){
                setAuthenticationInContext(new SecurityRealmAnonymousAuthentication());
                // don't return true; as we need to continue the filter chain on order to reach the servlet controller
                return false;
            }
        }
        return false;
    }

}
