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
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Slf4j
@AutoConfiguration
public class AutoConfigureMultiSecurityRealmsSupport {

    @ConditionalOnMissingBean(SecurityContextRepository.class)
    @Bean
    public SecurityContextRepository httpSessionSecurityContextRepository() {
        log.info("Creating a default SecurityContextRepository of type HttpSessionSecurityContextRepository");
        return new HttpSessionSecurityContextRepository();
    }

    @ConditionalOnMissingBean(MultiSecurityRealmAuthenticationFilter.class)
    @Bean
    public MultiSecurityRealmAuthenticationFilter multiSecurityRealmAuthenticationFilter(Set<SecurityRealm<?>> realms,
        SecurityContextRepository securityContextRepository) {
        log.info("Creating a default MultiSecurityRealmAuthenticationFilter");
        return new MultiSecurityRealmAuthenticationFilter(realms, securityContextRepository);
    }

    @ConditionalOnMissingBean(SecurityFilterChain.class)
    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http, MultiSecurityRealmAuthenticationFilter multiSecurityRealmAuthenticationFilter)
        throws Exception {
        log.info("Creating a default SecurityFilterChain");

        http.addFilterBefore(multiSecurityRealmAuthenticationFilter, AnonymousAuthenticationFilter.class);

        http.authorizeHttpRequests(configurer -> configurer.anyRequest().authenticated());

        // required for Spring Security 6.x OR disable CSRF (not recommended)
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName(null);
        http.csrf(configurer -> configurer
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .csrfTokenRequestHandler(requestHandler)
        );

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
