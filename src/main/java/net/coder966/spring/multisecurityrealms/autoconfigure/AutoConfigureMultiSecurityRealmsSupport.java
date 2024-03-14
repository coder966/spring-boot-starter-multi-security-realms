package net.coder966.spring.multisecurityrealms.autoconfigure;

import java.util.Set;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.expression.PermitRealmExpressionRoot;
import net.coder966.spring.multisecurityrealms.filter.MultiSecurityRealmAuthenticationFilter;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Slf4j
@AutoConfiguration
public class AutoConfigureMultiSecurityRealmsSupport {

    @ConditionalOnMissingBean(MultiSecurityRealmAuthenticationFilter.class)
    @Bean
    public MultiSecurityRealmAuthenticationFilter multiSecurityRealmAuthenticationFilter(SecurityRealmConfig config, Set<SecurityRealm> realms) {
        log.info("Creating a default MultiSecurityRealmAuthenticationFilter");
        return new MultiSecurityRealmAuthenticationFilter(config, realms);
    }

    @ConditionalOnMissingBean(SecurityFilterChain.class)
    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http, MultiSecurityRealmAuthenticationFilter multiSecurityRealmAuthenticationFilter)
        throws Exception {
        log.info("Creating a default SecurityFilterChain");

        http.addFilterBefore(multiSecurityRealmAuthenticationFilter, AnonymousAuthenticationFilter.class);
        http.authorizeHttpRequests(configurer -> configurer.anyRequest().authenticated());
        http.csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    static MethodSecurityExpressionHandler permitRealmMethodSecurityExpressionHandler() {
        return new DefaultMethodSecurityExpressionHandler(){
            @Override
            public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication, MethodInvocation mi) {
                StandardEvaluationContext context = (StandardEvaluationContext) super.createEvaluationContext(authentication, mi);
                MethodSecurityExpressionOperations delegate = (MethodSecurityExpressionOperations) context.getRootObject().getValue();
                PermitRealmExpressionRoot root = new PermitRealmExpressionRoot(delegate.getAuthentication());
                context.setRootObject(root);
                return context;
            }
        };
    }

}
