package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import net.coder966.spring.multisecurityrealms.autoconfigure.SecurityRealmConfig;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmHandler;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmHandlerScanner;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class MultiSecurityRealmAuthenticationFilter extends OncePerRequestFilter {

    private Set<SecurityRealmAuthenticationFilter> filters = new HashSet<>();

    public MultiSecurityRealmAuthenticationFilter(ApplicationContext context, SecurityRealmConfig config) {
        SecurityRealmHandlerScanner scanner = new SecurityRealmHandlerScanner();
        Collection<SecurityRealmHandler> securityRealmHandlers = scanner.scan(context);

        securityRealmHandlers.forEach(realm -> {
            filters.add(new SecurityRealmAuthenticationFilter(config, realm));
        });
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        for(SecurityRealmAuthenticationFilter filter : filters){
            boolean handled = filter.handle(request, response);
            if(handled){
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
