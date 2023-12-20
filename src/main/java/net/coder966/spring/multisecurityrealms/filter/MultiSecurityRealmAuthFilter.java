package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import net.coder966.spring.multisecurityrealms.model.Realm;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class MultiSecurityRealmAuthFilter extends OncePerRequestFilter {

    private final Set<Realm<?>> realms;

    MultiSecurityRealmAuthFilter(Set<Realm<?>> realms) {
        this.realms = realms;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        for(Realm<?> realm : realms){
            if(realm.getFilter().matchesLogin(request) || realm.getFilter().matchesLogout(request)){
                realm.getFilter().doFilter(request, response, filterChain);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
