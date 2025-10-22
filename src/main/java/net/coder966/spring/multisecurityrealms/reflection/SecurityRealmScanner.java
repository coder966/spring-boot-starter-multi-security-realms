package net.coder966.spring.multisecurityrealms.reflection;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.coder966.spring.multisecurityrealms.annotation.AnonymousAccess;
import net.coder966.spring.multisecurityrealms.annotation.AuthenticationStep;
import net.coder966.spring.multisecurityrealms.annotation.SecurityRealm;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.configuration.SecurityRealmConfigurationProperties;
import net.coder966.spring.multisecurityrealms.converter.SecurityRealmTokenCodec;
import net.coder966.spring.multisecurityrealms.filter.SecurityRealmAuthenticationFilter;
import net.coder966.spring.multisecurityrealms.mvc.AttributeValueRequestCondition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.convert.DurationStyle;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

public class SecurityRealmScanner {

    private static final Logger log = LoggerFactory.getLogger(SecurityRealmScanner.class);

    private final ApplicationContext context;
    private final Environment env;
    private final RequestMappingHandlerMapping requestMappingHandlerMapping;

    // scan result
    private Collection<SecurityRealmDescriptor> descriptors;
    private List<RequestMatcher> anonymousRequestMatchers;

    public SecurityRealmScanner(ApplicationContext context, Environment env) {
        this.context = context;
        this.env = env;

        // there could be multiple beans of this type, for example, when you include spring-boot-starter-actuator
        // We only need one handler to register authentication endpoints, we prefer to use the application "regular" handler
        // which has order=0 See WebMvcConfigurationSupport from spring-webmvc.
        this.requestMappingHandlerMapping = context.getBeansOfType(RequestMappingHandlerMapping.class).values().stream().findFirst().get();
    }

    public void scan() {
        scanForSecurityRealms();
        scanForAnonymousAccess();
    }

    public Collection<SecurityRealmDescriptor> getDescriptors() {
        return descriptors;
    }

    public List<RequestMatcher> getAnonymousRequestMatchers() {
        return anonymousRequestMatchers;
    }

    private void scanForSecurityRealms() {
        Map<String, SecurityRealmDescriptor> descriptors = new HashMap<>();

        for(Object bean : context.getBeansWithAnnotation(SecurityRealm.class).values()){
            final SecurityRealm realmAnnotation = bean.getClass().getSuperclass().getAnnotation(SecurityRealm.class);

            validateRealmAnnotation(realmAnnotation);

            SecurityRealmDescriptor descriptor = new SecurityRealmDescriptor(
                realmAnnotation.name(),
                buildAuthenticationEndpointRequestMatcher(realmAnnotation),
                realmAnnotation.firstStepName(),
                buildSecurityRealmTokenCodec(realmAnnotation),
                buildFullyAuthenticatedTokenTtl(realmAnnotation)
            );

            registerAuthenticationStepHandlers(realmAnnotation, bean);

            if(descriptors.containsKey(realmAnnotation.name())){
                throw new IllegalArgumentException("Invalid SecurityRealm name (" + realmAnnotation.name() + "). Realm name should be unique.");
            }
            descriptors.put(realmAnnotation.name(), descriptor);
        }

        this.descriptors = descriptors.values();
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
                .customCondition(new AttributeValueRequestCondition(SecurityRealmAuthenticationFilter.AUTHENTICATION_REQUEST_ATTRIBUTE_NAME, stepName))
                .build();
            
            requestMappingHandlerMapping.registerMapping(mappingInfo, realmBean, method);
        }
    }

    private RequestMatcher buildAuthenticationEndpointRequestMatcher(SecurityRealm realmAnnotation) {
        try{
            return new AntPathRequestMatcher(realmAnnotation.authenticationEndpoint(), HttpMethod.POST.name());
        }catch(Exception e){
            throw new IllegalArgumentException(
                    "Invalid authenticationEndpoint (" + realmAnnotation.authenticationEndpoint() + ") for SecurityRealm (" + realmAnnotation.name() + ")"
            );
        }
    }

    private SecurityRealmTokenCodec buildSecurityRealmTokenCodec(SecurityRealm realmAnnotation) {
        SecurityRealmConfigurationProperties defaultProperties = context.getBean(SecurityRealmConfigurationProperties.class);

        // determine the source of the value (annotation or properties)
        String signingSecret = realmAnnotation.signingSecret();
        if(signingSecret == null || signingSecret.trim().isEmpty()){
            log.warn("SecurityRealm (" + realmAnnotation.name() + ") does not specify a signing secret,"
                + " will use the default specified under the configuration property security-realm.signing-secret");
            signingSecret = defaultProperties.getSigningSecret();
        }

        // support placeholders in the expression
        signingSecret = env.resolveRequiredPlaceholders(signingSecret);

        return new SecurityRealmTokenCodec(signingSecret);
    }

    private Duration buildFullyAuthenticatedTokenTtl(SecurityRealm realmAnnotation) {
        SecurityRealmConfigurationProperties defaultProperties = context.getBean(SecurityRealmConfigurationProperties.class);

        // determine the source of the value (annotation or properties)
        String durationExpression = realmAnnotation.fullyAuthenticatedTokenTtl();
        if(durationExpression == null || durationExpression.trim().isEmpty()){
            log.warn("SecurityRealm (" + realmAnnotation.name() + ") does not specify a token expiration duration,"
                + " will use the default specified under the configuration property security-realm.fully-authenticated-token-ttl");
            durationExpression = defaultProperties.getFullyAuthenticatedTokenTtl().toString();
        }

        // support placeholders in the expression
        durationExpression = env.resolvePlaceholders(durationExpression);

        // parse
        Duration duration;
        try{
            duration = DurationStyle.detectAndParse(durationExpression);
        }catch(Exception e){
            throw new IllegalArgumentException(
                "Invalid TTL (" + durationExpression + ") for SecurityRealm (" + realmAnnotation.name() + ")"
            );
        }

        return duration;
    }

    private void scanForAnonymousAccess() {
        List<RequestMatcher> requestMatchers = new LinkedList<>();

        // use map, so that if a class is annotated with both @Controller and @RestController we don't process it twice
        Map<String, Object> beansMap = new HashMap<>();
        beansMap.putAll(context.getBeansWithAnnotation(Controller.class));
        beansMap.putAll(context.getBeansWithAnnotation(RestController.class));

        for(Object bean : beansMap.values()){
            Method[] methods = bean.getClass().getDeclaredMethods();
            for(Method method : methods){
                if(!method.isAnnotationPresent(AnonymousAccess.class)){
                    continue;
                }

                RequestMapping requestMapping = AnnotatedElementUtils.findMergedAnnotation(method, RequestMapping.class);

                if(requestMapping == null){
                    throw new IllegalArgumentException(
                        "@AnonymousAccess should be used on controller mapping methods only. The method (" + method + ") is not a controller method."
                    );
                }

                String[] paths = requestMapping.path();
                RequestMethod[] requestMethods = requestMapping.method();

                for (String path : paths) {
                    if (requestMethods.length == 0) { // No method restriction
                        requestMatchers.add(new AntPathRequestMatcher(path));
                    } else {
                        for (RequestMethod requestMethod : requestMethods) {
                            requestMatchers.add(new AntPathRequestMatcher(path, requestMethod.name()));
                        }
                    }
                }
            }
        }

        this.anonymousRequestMatchers = requestMatchers;
    }

}
