package net.coder966.spring.multisecurityrealms;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.coder966.spring.multisecurityrealms.exception.MultiRealmAuthException;
import net.coder966.spring.multisecurityrealms.model.MultiRealmAuth;
import net.coder966.spring.multisecurityrealms.model.Realm;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class MultiRealmAuthFilter extends OncePerRequestFilter {

    static final Map<String, Realm<?>> realmsByLoginUrl = new HashMap<>();
    static final Map<String, Realm<?>> realmsByLogoutUrl = new HashMap<>();

    // session attribute names
    private final String CURRENT_STEP_SESSION_ATTRIBUTE_NAME = "CURRENT_AUTH_STEP";

    // response headers
    public static final String NEXT_STEP_RESPONSE_HEADER_NAME = "X-Next-Auth-Step";
    public static final String ERROR_CODE_RESPONSE_HEADER_NAME = "X-Auth-Error-Code";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        if(!request.getMethod().equals("POST")){
            filterChain.doFilter(request, response);
            return;
        }

        Realm<?> loginRealm = realmsByLoginUrl.get(request.getRequestURI());
        if(loginRealm != null){
            handleLogin(loginRealm, request, response);
            return;
        }

        Realm<?> logoutRealm = realmsByLogoutUrl.get(request.getRequestURI());
        if(logoutRealm != null){
            handleLogout(logoutRealm, request, response);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void handleLogin(Realm<?> realm, HttpServletRequest request, HttpServletResponse response) {
        // get current auth step for this realm
        String authStepName = (String) request.getSession().getAttribute(CURRENT_STEP_SESSION_ATTRIBUTE_NAME);

        if(authStepName == null){ // first step
            try{
                final MultiRealmAuth<?> resultAuth = realm.getFirstStepAuthProvider().authenticate(request);
                afterAuthenticate(request, response, realm, resultAuth);
            }catch(MultiRealmAuthException e){
                setAuthErrorCode(response, e.getMessage());
            }
        }else{
            try{
                final MultiRealmAuth previousStepAuth = (MultiRealmAuth<?>) SecurityContextHolder.getContext().getAuthentication();
                final MultiRealmAuth<?> resultAuth = realm.getAuthSteps().get(authStepName).authenticate(previousStepAuth, request);
                afterAuthenticate(request, response, realm, resultAuth);
            }catch(MultiRealmAuthException e){
                setAuthErrorCode(response, e.getMessage());
            }
        }
    }

    private void handleLogout(Realm<?> realm, HttpServletRequest request, HttpServletResponse response) {
        request.getSession().setAttribute(CURRENT_STEP_SESSION_ATTRIBUTE_NAME, null);
        SecurityContextHolder.clearContext();
    }

    private void afterAuthenticate(HttpServletRequest request, HttpServletResponse response, Realm<?> realm, MultiRealmAuth<?> auth) {
        if(auth == null){
            throw new IllegalStateException("MultiRealmAuthProvider should not return null. "
                + "It should either throw MultiRealmAuthException or return a MultiRealmAuth object.");
        }

        SecurityContextHolder.getContext().setAuthentication(auth);

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
        Objects.requireNonNull(errorCode);
        response.setStatus(401);
        response.setHeader(ERROR_CODE_RESPONSE_HEADER_NAME, errorCode);
    }
}
