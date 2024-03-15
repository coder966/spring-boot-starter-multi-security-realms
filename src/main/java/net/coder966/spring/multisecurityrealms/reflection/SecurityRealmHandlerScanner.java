package net.coder966.spring.multisecurityrealms.reflection;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.coder966.spring.multisecurityrealms.annotation.AuthenticationStep;
import net.coder966.spring.multisecurityrealms.annotation.SecurityRealm;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

public class SecurityRealmHandlerScanner {

    public Collection<SecurityRealmHandler> scan(ApplicationContext context) {
        Map<String, Object> beans = context.getBeansWithAnnotation(SecurityRealm.class);
        return buildHandlers(beans.values());
    }

    private Collection<SecurityRealmHandler> buildHandlers(Collection<Object> beans) {
        Map<String, SecurityRealmHandler> handlers = new HashMap<>();

        for(Object bean : beans){
            SecurityRealm realmAnnotation = bean.getClass().getSuperclass().getAnnotation(SecurityRealm.class);
            String name = realmAnnotation.name();
            String authenticationEndpoint = realmAnnotation.authenticationEndpoint();
            String firstStepName = realmAnnotation.firstStepName();
            String[] publicApis = realmAnnotation.publicApis();

            Map<String, AuthenticationStepInvoker> authenticationStepInvokers = buildAuthenticationStepInvokers(name, bean);

            if(name == null || name.trim().length() != name.length()){
                throw new IllegalArgumentException("Invalid SecurityRealm name (" + name + ")");
            }
            if(handlers.containsKey(name)){
                throw new IllegalArgumentException("Invalid SecurityRealm name (" + name + ")");
            }

            RequestMatcher authenticationEndpointRequestMatcher;
            try{
                authenticationEndpointRequestMatcher = new AntPathRequestMatcher(authenticationEndpoint);
            }catch(Exception e){
                throw new IllegalArgumentException("Invalid authenticationEndpoint (" + authenticationEndpoint + ") for SecurityRealm (" + name + ")");
            }

            if(firstStepName == null || !authenticationStepInvokers.containsKey(firstStepName)){
                throw new IllegalArgumentException("Invalid firstStepName (" + firstStepName + ") for SecurityRealm (" + name + ")");
            }

            List<RequestMatcher> publicApisRequestMatchers = new ArrayList<>(publicApis.length);
            for(String pattern : publicApis){
                try{
                    publicApisRequestMatchers.add(new AntPathRequestMatcher(pattern));
                }catch(Exception e){
                    throw new IllegalArgumentException("Invalid publicApis (" + pattern + ") for SecurityRealm (" + name + ").");
                }
            }

            SecurityRealmHandler handler = new SecurityRealmHandler(
                name,
                authenticationEndpointRequestMatcher,
                firstStepName,
                publicApisRequestMatchers,
                authenticationStepInvokers
            );

            handlers.put(name, handler);
        }

        return handlers.values();
    }

    private Map<String, AuthenticationStepInvoker> buildAuthenticationStepInvokers(String realmName, Object realmBean) {
        Map<String, AuthenticationStepInvoker> stepInvoker = new HashMap<>();

        for(Method method : realmBean.getClass().getSuperclass().getDeclaredMethods()){
            AuthenticationStep stepAnnotation = method.getAnnotation(AuthenticationStep.class);
            String stepName = stepAnnotation.value();

            if(stepName == null || stepName.trim().length() != stepName.length() || stepName.isBlank()){
                throw new IllegalArgumentException("Invalid AuthenticationStep name (" + stepName + ") for SecurityRealm (" + realmName + ")");
            }
            if(!method.getReturnType().isAssignableFrom(SecurityRealmAuthentication.class)){
                throw new IllegalArgumentException("Invalid return type (" + method.getReturnType().getCanonicalName() + ") "
                    + "of AuthenticationStep (" + stepName + ") for SecurityRealm (" + realmName + ")");
            }

            Parameter[] parameters = method.getParameters();
            AuthenticationStepParameterType[] parameterTypes = new AuthenticationStepParameterType[parameters.length];

            for(int i = 0; i < parameters.length; i++){
                Parameter parameter = parameters[i];
                AuthenticationStepParameterType parameterType;

                if(ServletRequest.class.isAssignableFrom(parameter.getType())){
                    parameterType = AuthenticationStepParameterType.REQUEST;
                }else if(ServletResponse.class.isAssignableFrom(parameter.getType())){
                    parameterType = AuthenticationStepParameterType.RESPONSE;
                }else if(Authentication.class.isAssignableFrom(parameter.getType())){
                    parameterType = AuthenticationStepParameterType.AUTHENTICATION;
                }else if(parameter.getType().getAnnotation(RequestBody.class) != null){
                    parameterType = AuthenticationStepParameterType.BODY;
                }else if(parameter.getType().getAnnotation(RequestHeader.class) != null && Map.class.isAssignableFrom(parameter.getType())){
                    parameterType = AuthenticationStepParameterType.HEADERS;
                }else{
                    parameterType = AuthenticationStepParameterType.UNKNOWN;
                }

                parameterTypes[i] = parameterType;
            }


            // each step name should have a config to call
            AuthenticationStepInvoker authenticationStepInvoker = new AuthenticationStepInvoker(realmBean, method, parameterTypes);
            stepInvoker.put(stepName, authenticationStepInvoker);
        }

        return stepInvoker;
    }
}
