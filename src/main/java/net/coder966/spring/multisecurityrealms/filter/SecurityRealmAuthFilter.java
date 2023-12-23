package net.coder966.spring.multisecurityrealms.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;
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

@Slf4j
public class SecurityRealmAuthFilter<T> extends OncePerRequestFilter {

    private final SecurityRealm<T> realm;
    private final SecurityContextRepository securityContextRepository;

    // session attribute names
    private final String CURRENT_STEP_SESSION_ATTRIBUTE_NAME = "CURRENT_AUTH_STEP";

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


        // get current auth step for this realm
        String authStepName = (String) request.getSession().getAttribute(CURRENT_STEP_SESSION_ATTRIBUTE_NAME);


        try{
            final SecurityRealmAuth<T> resultAuth;

            if(authStepName == null){ // first step
                resultAuth = realm.getFirstStepAuthProvider().authenticate(request);
            }else{
                SecurityRealmAuth<T> previousStepAuth = (SecurityRealmAuth<T>) SecurityContextHolder.getContext().getAuthentication();
                resultAuth = realm.getAuthSteps().get(authStepName).authenticate(previousStepAuth, request);
            }

            afterAuthenticate(request, response, realm, resultAuth);
        }catch(SecurityRealmAuthException e){
            setAuthErrorCode(response, e.getMessage());
        }catch(AuthenticationException e){
            setAuthErrorCode(response, null);
        }
    }

    private void handleLogout(HttpServletRequest request, HttpServletResponse response) {
        request.getSession().setAttribute(CURRENT_STEP_SESSION_ATTRIBUTE_NAME, null);

        SecurityContextHolder.clearContext();
        securityContextRepository.saveContext(SecurityContextHolder.createEmptyContext(), request, response);

        response.setStatus(200);
    }

    private void afterAuthenticate(HttpServletRequest request, HttpServletResponse response, SecurityRealm<?> realm, SecurityRealmAuth<?> auth) {
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
            setNextAuthStep(request, response, auth.getNextAuthStep());
        }else{
            auth.getAuthorities().add(new SimpleGrantedAuthority("ROLE_" + realm.getRolePrefix()));
            request.getSession().setAttribute(CURRENT_STEP_SESSION_ATTRIBUTE_NAME, null);
        }
    }

    private void setNextAuthStep(HttpServletRequest request, HttpServletResponse response, String nextStepName) {
        Objects.requireNonNull(nextStepName);
        request.getSession().setAttribute(CURRENT_STEP_SESSION_ATTRIBUTE_NAME, nextStepName);
        response.setStatus(200);
        response.setHeader(NEXT_STEP_RESPONSE_HEADER_NAME, nextStepName);
    }

    private void setAuthErrorCode(HttpServletResponse response, String errorCode) {
        response.setStatus(401);
        response.setHeader(ERROR_CODE_RESPONSE_HEADER_NAME, errorCode == null ? "" : errorCode);
    }
}
