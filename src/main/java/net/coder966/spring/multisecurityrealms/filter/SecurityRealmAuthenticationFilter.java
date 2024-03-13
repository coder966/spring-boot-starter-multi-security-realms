package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAnonymousAuthentication;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
public class SecurityRealmAuthenticationFilter<T> extends OncePerRequestFilter {

    private final SecurityRealm<T> realm;
    private final SecurityContextRepository securityContextRepository;

    // response headers
    private final String NEXT_STEP_RESPONSE_HEADER_NAME = "X-Next-Auth-Step";
    private final String ERROR_CODE_RESPONSE_HEADER_NAME = "X-Auth-Error-Code";

    public SecurityRealmAuthenticationFilter(SecurityRealm<T> realm, SecurityContextRepository securityContextRepository) {
        this.realm = realm;
        this.securityContextRepository = securityContextRepository;
    }

    public boolean matches(HttpServletRequest request) {
        return matchesLogin(request) || matchesLogout(request) || matchesPublicApi(request);
    }

    private boolean matchesLogin(HttpServletRequest request) {
        return request.getMethod().equals("POST") && request.getRequestURI().equals(realm.getLoginUrl());
    }

    private boolean matchesLogout(HttpServletRequest request) {
        return request.getMethod().equals("POST") && request.getRequestURI().equals(realm.getLogoutUrl());
    }

    private boolean matchesPublicApi(HttpServletRequest request) {
        return realm.getPublicApisRequestMatchers().stream().anyMatch(requestMatcher -> requestMatcher.matches(request));
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

        if(matchesPublicApi(request)){
            log.debug("handling public api");
            handlePublicApi(request, response);
            // don't return, we need to continue the filter chain on order to reach the servlet controller
        }

        filterChain.doFilter(request, response);
    }

    private void handleLogin(HttpServletRequest request, HttpServletResponse response) {
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

        if(currentAuth != null && !(currentAuth instanceof SecurityRealmAuthentication)){
            throw new SecurityRealmAuthenticationException("User already authenticated with a custom authentication not supported by this filter.");
        }

        SecurityRealmAuthentication<T> currentRealmAuth = (SecurityRealmAuthentication<T>) currentAuth;
        String step = currentRealmAuth == null ? null : currentRealmAuth.getNextAuthStep();

        try{
            SecurityRealmAuthentication<T> resultAuth = realm.authenticate(request, step, currentRealmAuth);
            afterAuthenticate(request, response, realm, resultAuth);
        }catch(AuthenticationException e){
            response.setStatus(401);
            response.setHeader(ERROR_CODE_RESPONSE_HEADER_NAME, e.getMessage());
        }
    }

    private void handleLogout(HttpServletRequest request, HttpServletResponse response) {
        saveAuthInContextRepository(request, response, null);
    }

    private void handlePublicApi(HttpServletRequest request, HttpServletResponse response) {
        // don't use AnonymousAuthenticationToken because it will be rejected down via AuthorizationFilter
        saveAuthInContextRepository(request, response, new SecurityRealmAnonymousAuthentication());
    }

    private void afterAuthenticate(HttpServletRequest request, HttpServletResponse response, SecurityRealm<T> realm, SecurityRealmAuthentication<T> auth) {
        if(auth == null){
            throw new IllegalStateException("MultiRealmAuthenticationProvider should not return null. "
                + "It should either throw MultiRealmAuthException or return a MultiRealmAuth object.");
        }

        if(auth.getPrincipal() == null){
            throw new IllegalStateException("Principal should not be null.");
        }

        auth.setRealmName(realm.getName());

        saveAuthInContextRepository(request, response, auth);

        if(auth.getNextAuthStep() != null){
            response.setHeader(NEXT_STEP_RESPONSE_HEADER_NAME, auth.getNextAuthStep());
        }
    }

    private void saveAuthInContextRepository(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        SecurityContextHolder.clearContext();
        SecurityContext newContext = SecurityContextHolder.createEmptyContext();
        newContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(newContext);
        securityContextRepository.saveContext(newContext, request, response);
    }

}
