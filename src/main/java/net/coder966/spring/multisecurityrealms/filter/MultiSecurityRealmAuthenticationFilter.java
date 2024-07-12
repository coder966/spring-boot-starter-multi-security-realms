package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import net.coder966.spring.multisecurityrealms.context.SecurityRealmContext;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmDescriptor;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmScanner;
import org.springframework.web.filter.OncePerRequestFilter;

public class MultiSecurityRealmAuthenticationFilter extends OncePerRequestFilter {

    private final Set<SecurityRealmAuthenticationFilter> filters = new HashSet<>();

    public MultiSecurityRealmAuthenticationFilter(SecurityRealmScanner scanner) {
        Collection<SecurityRealmDescriptor> securityRealmDescriptors = scanner.scan();
        securityRealmDescriptors.forEach(realm -> filters.add(new SecurityRealmAuthenticationFilter(realm)));
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

        // clear these to avoid misuse by library consumers
        SecurityRealmContext.setDescriptor(null);
        SecurityRealmContext.setCurrentStep(null);
    }
}
