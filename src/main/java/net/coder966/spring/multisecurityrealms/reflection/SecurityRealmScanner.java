package net.coder966.spring.multisecurityrealms.reflection;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.coder966.spring.multisecurityrealms.annotation.AuthenticationStep;
import net.coder966.spring.multisecurityrealms.annotation.SecurityRealm;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.converter.AuthenticationTokenConverter;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

public class SecurityRealmScanner {

    private final ApplicationContext context;
    private final RequestMappingHandlerMapping requestMappingHandlerMapping;
    private final AuthenticationTokenConverter authenticationTokenConverter;

    public SecurityRealmScanner(ApplicationContext context) {
        this.context = context;
        this.requestMappingHandlerMapping = context.getBean(RequestMappingHandlerMapping.class);
        this.authenticationTokenConverter = context.getBean(AuthenticationTokenConverter.class);
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

            registerAuthenticationStepHandlers(name, authenticationEndpoint, bean);

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
                authenticationTokenConverter
            );

            descriptors.put(name, descriptor);
        }

        return descriptors.values();
    }

    private void registerAuthenticationStepHandlers(String realmName, String authenticationEndpoint, Object realmBean) {
        Set<String> stepNames = new HashSet<>();

        for(Method method : realmBean.getClass().getSuperclass().getDeclaredMethods()){
            AuthenticationStep stepAnnotation = method.getAnnotation(AuthenticationStep.class);
            if(stepAnnotation == null){
                continue;
            }

            String stepName = stepAnnotation.value();
            if(stepName == null || stepName.trim().length() != stepName.length() || stepName.isBlank()){
                throw new IllegalArgumentException("Invalid AuthenticationStep name (" + stepName + ") for SecurityRealm (" + realmName + ")");
            }

            if(stepNames.contains(stepName)){
                throw new IllegalArgumentException(
                    "Found more than one AuthenticationStep with the same name (" + stepName + ") for SecurityRealm (" + realmName + ")");
            }

            if(!method.getReturnType().isAssignableFrom(SecurityRealmAuthentication.class)){
                throw new IllegalArgumentException("Invalid return type (" + method.getReturnType().getCanonicalName() + ") "
                    + "of AuthenticationStep (" + stepName + ") for SecurityRealm (" + realmName + "). "
                    + "It should be SecurityRealmAuthentication.");
            }

            stepNames.add(stepName);

            RequestMappingInfo mappingInfo = RequestMappingInfo
                .paths(authenticationEndpoint)
                .methods(RequestMethod.POST)
                .params("AuthenticationStep-" + stepName)
                .build();
            
            requestMappingHandlerMapping.registerMapping(mappingInfo, realmBean, method);
        }
    }
}
