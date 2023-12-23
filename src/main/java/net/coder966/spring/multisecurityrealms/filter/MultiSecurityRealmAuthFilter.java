package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import org.springframework.web.filter.OncePerRequestFilter;

public class MultiSecurityRealmAuthFilter extends OncePerRequestFilter {

    private final Set<SecurityRealmAuthFilter<?>> filters = new HashSet<>();

    public MultiSecurityRealmAuthFilter(Set<SecurityRealm<?>> realms) {
        realms.forEach(realm -> {
            filters.add(new SecurityRealmAuthFilter<>(realm));
        });
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        for(SecurityRealmAuthFilter<?> filter : filters){
            if(filter.matchesLogin(request) || filter.matchesLogout(request)){
                filter.doFilter(request, response, filterChain);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
