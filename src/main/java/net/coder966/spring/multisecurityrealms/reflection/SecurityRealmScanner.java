package net.coder966.spring.multisecurityrealms.reflection;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

@Component
public class SecurityRealmScanner {

    private final ApplicationContext context;
    private final ObjectMapper objectMapper;

    public SecurityRealmScanner(ApplicationContext context) {
        this.context = context;
        this.objectMapper = context.getBean(ObjectMapper.class);
    }

    public Collection<SecurityRealmDescriptor> scan() {
        Map<String, Object> beans = context.getBeansWithAnnotation(SecurityRealm.class);
        return buildDescriptors(beans.values());
    }

    private Collection<SecurityRealmDescriptor> buildDescriptors(Collection<Object> beans) {
        Map<String, SecurityRealmDescriptor> descriptors = new HashMap<>();

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
            if(descriptors.containsKey(name)){
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

            SecurityRealmDescriptor descriptor = new SecurityRealmDescriptor(
                name,
                authenticationEndpointRequestMatcher,
                firstStepName,
                publicApisRequestMatchers,
                authenticationStepInvokers
            );

            descriptors.put(name, descriptor);
        }

        return descriptors.values();
    }

    private Map<String, AuthenticationStepInvoker> buildAuthenticationStepInvokers(String realmName, Object realmBean) {
        Map<String, AuthenticationStepInvoker> stepInvoker = new HashMap<>();

        for(Method method : realmBean.getClass().getSuperclass().getDeclaredMethods()){
            AuthenticationStep stepAnnotation = method.getAnnotation(AuthenticationStep.class);
            if(stepAnnotation == null){
                continue;
            }

            String stepName = stepAnnotation.value();
            if(stepName == null || stepName.trim().length() != stepName.length() || stepName.isBlank()){
                throw new IllegalArgumentException("Invalid AuthenticationStep name (" + stepName + ") for SecurityRealm (" + realmName + ")");
            }
            
            if(!method.getReturnType().isAssignableFrom(SecurityRealmAuthentication.class)){
                throw new IllegalArgumentException("Invalid return type (" + method.getReturnType().getCanonicalName() + ") "
                    + "of AuthenticationStep (" + stepName + ") for SecurityRealm (" + realmName + ")");
            }

            Parameter[] parameters = method.getParameters();
            AuthenticationStepParameterDetails[] parameterDetails = new AuthenticationStepParameterDetails[parameters.length];

            for(int i = 0; i < parameters.length; i++){
                Parameter parameter = parameters[i];

                if(ServletRequest.class.isAssignableFrom(parameter.getType())){
                    parameterDetails[i] = new AuthenticationStepParameterDetails(AuthenticationStepParameterType.REQUEST);
                }else if(ServletResponse.class.isAssignableFrom(parameter.getType())){
                    parameterDetails[i] = new AuthenticationStepParameterDetails(AuthenticationStepParameterType.RESPONSE);
                }else if(Authentication.class.isAssignableFrom(parameter.getType())){
                    parameterDetails[i] = new AuthenticationStepParameterDetails(AuthenticationStepParameterType.AUTHENTICATION);
                }else if(parameter.getAnnotation(RequestBody.class) != null){
                    parameterDetails[i] = new AuthenticationStepParameterDetails(AuthenticationStepParameterType.BODY)
                        .withDetails("class", parameter.getType());
                }else if(parameter.getAnnotation(RequestHeader.class) != null){
                    parameterDetails[i] = new AuthenticationStepParameterDetails(AuthenticationStepParameterType.HEADER)
                        .withDetails("class", parameter.getType())
                        .withDetails("name", parameter.getAnnotation(RequestHeader.class).value());
                }else if(parameter.getAnnotation(RequestParam.class) != null){
                    parameterDetails[i] = new AuthenticationStepParameterDetails(AuthenticationStepParameterType.REQUEST_PARAM)
                        .withDetails("class", parameter.getType())
                        .withDetails("name", parameter.getAnnotation(RequestParam.class).value());
                }else{
                    parameterDetails[i] = new AuthenticationStepParameterDetails(AuthenticationStepParameterType.UNKNOWN);
                }

            }


            // each step name should have a config to call
            AuthenticationStepInvoker authenticationStepInvoker = new AuthenticationStepInvoker(
                objectMapper,
                realmBean,
                method,
                parameterDetails
            );
            stepInvoker.put(stepName, authenticationStepInvoker);
        }

        return stepInvoker;
    }
}
