package net.coder966.spring.multisecurityrealms.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import net.coder966.spring.multisecurityrealms.converter.AuthenticationTokenConverter;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmDescriptor;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmScanner;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class MultiSecurityRealmAuthenticationFilter extends OncePerRequestFilter {

    private final Set<SecurityRealmAuthenticationFilter> filters = new HashSet<>();

    public MultiSecurityRealmAuthenticationFilter(
        SecurityRealmScanner scanner,
        AuthenticationTokenConverter authenticationTokenConverter,
        ObjectMapper objectMapper
    ) {

        Collection<SecurityRealmDescriptor> securityRealmDescriptors = scanner.scan();

        securityRealmDescriptors.forEach(realm -> {
            filters.add(new SecurityRealmAuthenticationFilter(realm, authenticationTokenConverter, objectMapper));
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
