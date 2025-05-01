package net.coder966.spring.multisecurityrealms.reflection;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.annotation.AuthenticationStep;
import net.coder966.spring.multisecurityrealms.annotation.SecurityRealm;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.configuration.SecurityRealmConfigurationProperties;
import net.coder966.spring.multisecurityrealms.converter.SecurityRealmTokenCodec;
import org.springframework.boot.convert.DurationStyle;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@Slf4j
public class SecurityRealmScanner {

    private final ApplicationContext context;
    private final Environment env;
    private final RequestMappingHandlerMapping requestMappingHandlerMapping;

    public SecurityRealmScanner(ApplicationContext context, Environment env) {
        this.context = context;
        this.env = env;

        // there could be multiple beans of this type, for example, when you include spring-boot-starter-actuator
        // We only need one handler to register authentication endpoints, we prefer to use the application "regular" handler
        // which has order=0 See WebMvcConfigurationSupport from spring-webmvc.
        this.requestMappingHandlerMapping = context.getBeansOfType(RequestMappingHandlerMapping.class).values().stream().findFirst().get();
    }

    public Collection<SecurityRealmDescriptor> scan() {
        Map<String, Object> beans = context.getBeansWithAnnotation(SecurityRealm.class);
        return buildDescriptors(beans.values());
    }

    private Collection<SecurityRealmDescriptor> buildDescriptors(Collection<Object> beans) {
        Map<String, SecurityRealmDescriptor> descriptors = new HashMap<>();

        for(Object bean : beans){
            final SecurityRealm realmAnnotation = bean.getClass().getSuperclass().getAnnotation(SecurityRealm.class);

            validateRealmAnnotation(realmAnnotation);

            SecurityRealmDescriptor descriptor = new SecurityRealmDescriptor(
                realmAnnotation.name(),
                buildAuthenticationEndpointRequestMatcher(realmAnnotation),
                realmAnnotation.firstStepName(),
                buildPublicApisRequestMatchers(realmAnnotation),
                buildSecurityRealmTokenCodec(realmAnnotation)
            );

            registerAuthenticationStepHandlers(realmAnnotation, bean);

            if(descriptors.containsKey(realmAnnotation.name())){
                throw new IllegalArgumentException("Invalid SecurityRealm name (" + realmAnnotation.name() + "). Realm name should be unique.");
            }
            descriptors.put(realmAnnotation.name(), descriptor);
        }

        return descriptors.values();
    }

    private void validateRealmAnnotation(SecurityRealm realmAnnotation) {
        String name = realmAnnotation.name();

        if(name == null || name.trim().length() != name.length()){
            throw new IllegalArgumentException("Invalid SecurityRealm name (" + name + ")");
        }
    }

    private void registerAuthenticationStepHandlers(SecurityRealm realmAnnotation, Object realmBean) {
        Set<String> stepNames = new HashSet<>();

        for(Method method : realmBean.getClass().getSuperclass().getDeclaredMethods()){
            AuthenticationStep stepAnnotation = method.getAnnotation(AuthenticationStep.class);
            if(stepAnnotation == null){
                continue;
            }

            String stepName = stepAnnotation.value();
            if(stepName == null || stepName.trim().length() != stepName.length() || stepName.isBlank()){
                throw new IllegalArgumentException("Invalid AuthenticationStep name (" + stepName + ") for SecurityRealm (" + realmAnnotation.name() + ")");
            }

            if(stepNames.contains(stepName)){
                throw new IllegalArgumentException(
                        "Found more than one AuthenticationStep with the same name (" + stepName + ") for SecurityRealm (" + realmAnnotation.name() + ")");
            }

            if(!method.getReturnType().isAssignableFrom(SecurityRealmAuthentication.class)){
                throw new IllegalArgumentException("Invalid return type (" + method.getReturnType().getCanonicalName() + ") "
                        + "of AuthenticationStep (" + stepName + ") for SecurityRealm (" + realmAnnotation.name() + "). "
                    + "It should be SecurityRealmAuthentication.");
            }

            stepNames.add(stepName);

            RequestMappingInfo mappingInfo = RequestMappingInfo
                    .paths(realmAnnotation.authenticationEndpoint())
                .methods(RequestMethod.POST)
                .params("AuthenticationStep-" + stepName)
                .build();
            
            requestMappingHandlerMapping.registerMapping(mappingInfo, realmBean, method);
        }
    }

    private RequestMatcher buildAuthenticationEndpointRequestMatcher(SecurityRealm realmAnnotation) {
        try{
            return new AntPathRequestMatcher(realmAnnotation.authenticationEndpoint());
        }catch(Exception e){
            throw new IllegalArgumentException(
                    "Invalid authenticationEndpoint (" + realmAnnotation.authenticationEndpoint() + ") for SecurityRealm (" + realmAnnotation.name() + ")"
            );
        }
    }

    private List<RequestMatcher> buildPublicApisRequestMatchers(SecurityRealm realmAnnotation) {
        List<RequestMatcher> requestMatchers = new ArrayList<>(realmAnnotation.publicApis().length);
        for(String pattern : realmAnnotation.publicApis()){
            try{
                requestMatchers.add(new AntPathRequestMatcher(pattern));
            }catch(Exception e){
                throw new IllegalArgumentException(
                        "Invalid publicApis (" + pattern + ") for SecurityRealm (" + realmAnnotation.name() + ")"
                );
            }
        }
        return requestMatchers;
    }

    private SecurityRealmTokenCodec buildSecurityRealmTokenCodec(SecurityRealm realmAnnotation) {
        SecurityRealmConfigurationProperties defaultProperties = context.getBean(SecurityRealmConfigurationProperties.class);

        String signingSecret = realmAnnotation.signingSecret();
        if(signingSecret == null || signingSecret.trim().isEmpty()){
            log.warn("SecurityRealm (" + realmAnnotation.name() + ") does not specify a signing secret,"
                + " will use the default specified under the configuration property security-realm.signing-secret");
            signingSecret = defaultProperties.getSigningSecret();
        }
        signingSecret = env.resolveRequiredPlaceholders(signingSecret);

        String tokenExpirationDurationString = realmAnnotation.tokenExpirationDuration();
        if(tokenExpirationDurationString == null || tokenExpirationDurationString.trim().isEmpty()){
            log.warn("SecurityRealm (" + realmAnnotation.name() + ") does not specify a token expiration duration,"
                + " will use the default specified under the configuration property security-realm.token-expiration-duration");
            tokenExpirationDurationString = defaultProperties.getTokenExpirationDuration().toString();
        }
        tokenExpirationDurationString = env.resolvePlaceholders(tokenExpirationDurationString);
        Duration tokenExpirationDuration;
        try{
            tokenExpirationDuration = DurationStyle.detectAndParse(tokenExpirationDurationString);
        }catch(Exception e){
            throw new IllegalArgumentException(
                "Invalid tokenExpirationDuration (" + tokenExpirationDurationString + ") for SecurityRealm (" + realmAnnotation.name() + ")"
            );
        }

        return new SecurityRealmTokenCodec(signingSecret, tokenExpirationDuration);
    }
}
