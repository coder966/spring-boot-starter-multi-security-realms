package net.coder966.spring.multisecurityrealms.model;

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Getter
public abstract class SecurityRealm {

    private final String name;
    private final String loginUrl;
    private final List<RequestMatcher> publicApisRequestMatchers = new ArrayList<>();

    public SecurityRealm(String name, String loginUrl) {
        if(name == null || name.length() < 2 || name.trim().length() != name.length()){
            throw new IllegalArgumentException("Invalid realm name: " + name);
        }

        if(loginUrl == null || loginUrl.trim().length() != loginUrl.length()){
            throw new IllegalArgumentException("Invalid loginUrl: " + loginUrl);
        }

        this.name = name;
        this.loginUrl = loginUrl;

        List<RequestMatcher> publicApis = getPublicApis();
        if(publicApis != null){
            publicApisRequestMatchers.addAll(publicApis);
        }
    }

    /**
     * This is the authentication handler. Login requests will be forwarded here.
     *
     * It supports multi factor authentication (MFA), for example 2FA with OTP etc...
     *
     * If the authentication is successful, return a SecurityRealmAuthentication. To indicate the user must go through another factor
     * of authentication, pass that step name to the constructor of SecurityRealmAuthentication.
     *
     * When the user authenticate for that additional step, the same handler will be called with the appropriate step name.
     *
     * @param request The request.
     * @param step Step name. Null for the first step.
     * @param previousStepAuth The current user authentication. Null for the first step.
     *
     * @return the user authentication object in case of successful authentication.
     */
    public abstract SecurityRealmAuthentication authenticate(HttpServletRequest request, String step, SecurityRealmAuthentication previousStepAuth);

    /**
     * If you want, you can define endpoints here and they will be made publicly available without authentication.
     *
     * @return A list of request matchers
     */
    public abstract List<RequestMatcher> getPublicApis();

}
