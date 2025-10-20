package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmScanner;
import org.springframework.context.ApplicationContext;
import org.springframework.web.filter.OncePerRequestFilter;

public class MultiSecurityRealmAuthenticationFilter extends OncePerRequestFilter {

    private final List<AbstractAuthenticationFilter> filters = new LinkedList<>();

    public MultiSecurityRealmAuthenticationFilter(ApplicationContext context, SecurityRealmScanner scanner) {
        scanner.scan();

        scanner
            .getDescriptors()
            .forEach(realm -> filters.add(new SecurityRealmAuthenticationFilter(context, realm)));

        // must be at the end, because if the user is authenticated, why clear the user authentication from the context, right ?
        filters.add(new AnonymousAccessAuthenticationFilter(scanner.getAnonymousRequestMatchers()));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        for(AbstractAuthenticationFilter filter : filters){
            boolean handled = filter.handle(request, response);
            if(handled){
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
