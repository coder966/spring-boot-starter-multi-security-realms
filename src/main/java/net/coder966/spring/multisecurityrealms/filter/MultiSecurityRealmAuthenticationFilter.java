package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

public class MultiSecurityRealmAuthenticationFilter extends OncePerRequestFilter {

    private final Set<SecurityRealmAuthenticationFilter<?>> filters = new HashSet<>();

    public MultiSecurityRealmAuthenticationFilter(Set<SecurityRealm<?>> realms, SecurityContextRepository securityContextRepository) {
        realms.forEach(realm -> {
            filters.add(new SecurityRealmAuthenticationFilter<>(realm, securityContextRepository));
        });
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        for(SecurityRealmAuthenticationFilter<?> filter : filters){
            if(filter.matches(request)){
                filter.doFilter(request, response, filterChain);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
