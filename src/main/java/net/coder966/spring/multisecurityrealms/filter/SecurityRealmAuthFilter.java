package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthException;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuth;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Slf4j
public class SecurityRealmAuthFilter<T> extends OncePerRequestFilter {

    private final SecurityRealm<T> realm;
    private final SecurityContextRepository securityContextRepository;

    // response headers
    private final String NEXT_STEP_RESPONSE_HEADER_NAME = "X-Next-Auth-Step";
    private final String ERROR_CODE_RESPONSE_HEADER_NAME = "X-Auth-Error-Code";

    public SecurityRealmAuthFilter(SecurityRealm<T> realm, SecurityContextRepository securityContextRepository) {
        this.realm = realm;
        this.securityContextRepository = securityContextRepository;
    }

    public boolean matchesLogin(HttpServletRequest request) {
        return request.getMethod().equals("POST") && request.getRequestURI().equals(realm.getLoginUrl());
    }

    public boolean matchesLogout(HttpServletRequest request) {
        return request.getMethod().equals("POST") && request.getRequestURI().equals(realm.getLogoutUrl());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        if(matchesLogin(request)){
            log.debug("handling login");
            handleLogin(request, response);
            return;
        }

        if(matchesLogout(request)){
            log.debug("handling logout");
            handleLogout(request, response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void handleLogin(HttpServletRequest request, HttpServletResponse response) {
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

        if(currentAuth != null && !(currentAuth instanceof SecurityRealmAuth)){
            throw new SecurityRealmAuthException("User already authenticated with a custom authentication not supported by this filter.");
        }

        SecurityRealmAuth<T> currentRealmAuth = (SecurityRealmAuth<T>) currentAuth;

        try{
            final SecurityRealmAuth<T> resultAuth;

            if(currentRealmAuth == null || currentRealmAuth.getNextAuthStep() == null){ // first step
                resultAuth = realm.getFirstStepAuthProvider().authenticate(request);
            }else{
                resultAuth = realm.getAuthSteps().get(currentRealmAuth.getNextAuthStep()).authenticate(currentRealmAuth, request);
            }

            afterAuthenticate(request, response, realm, resultAuth);
        }catch(AuthenticationException e){
            response.setStatus(401);
            response.setHeader(ERROR_CODE_RESPONSE_HEADER_NAME, e.getMessage());
        }
    }

    private void handleLogout(HttpServletRequest request, HttpServletResponse response) {
        SecurityContextHolder.clearContext();
        securityContextRepository.saveContext(SecurityContextHolder.createEmptyContext(), request, response);
    }

    private void afterAuthenticate(HttpServletRequest request, HttpServletResponse response, SecurityRealm<T> realm, SecurityRealmAuth<T> auth) {
        if(auth == null){
            throw new IllegalStateException("MultiRealmAuthProvider should not return null. "
                + "It should either throw MultiRealmAuthException or return a MultiRealmAuth object.");
        }

        if(auth.getPrincipal() == null){
            throw new IllegalStateException("Principal should not be null.");
        }

        SecurityContext newContext = SecurityContextHolder.createEmptyContext();
        newContext.setAuthentication(auth);
        securityContextRepository.saveContext(newContext, request, response);

        if(auth.getNextAuthStep() != null){
            response.setHeader(NEXT_STEP_RESPONSE_HEADER_NAME, auth.getNextAuthStep());
            return;
        }

        auth.getAuthorities().add(new SimpleGrantedAuthority("ROLE_" + realm.getRolePrefix()));
    }

}
