package net.coder966.spring.multisecurityrealms.configuration;

import net.coder966.spring.multisecurityrealms.advice.SecurityRealmControllerAdvice;
import net.coder966.spring.multisecurityrealms.expression.PermitRealmMethodSecurityExpressionHandler;
import net.coder966.spring.multisecurityrealms.filter.MultiSecurityRealmAuthenticationFilter;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@AutoConfiguration
public class AutoConfigureMultiSecurityRealmsSupport {

    private static final Logger log = LoggerFactory.getLogger(AutoConfigureMultiSecurityRealmsSupport.class);

    @Bean
    @ConditionalOnMissingBean(SecurityRealmConfigurationProperties.class)
    public SecurityRealmConfigurationProperties defaultSecurityRealmConfigurationProperties() {
        return new SecurityRealmConfigurationProperties();
    }

    @Bean
    public SecurityRealmControllerAdvice defaultSecurityRealmControllerAdvice() {
        return new SecurityRealmControllerAdvice();
    }

    @Bean
    public SecurityRealmScanner defaultSecurityRealmScanner(ApplicationContext context, Environment env) {
        return new SecurityRealmScanner(context, env);
    }

    @Bean
    public MultiSecurityRealmAuthenticationFilter defaultMultiSecurityRealmAuthenticationFilter(
        ApplicationContext context, SecurityRealmScanner securityRealmScanner
    ) {
        return new MultiSecurityRealmAuthenticationFilter(context, securityRealmScanner);
    }

    @Bean
    public PermitRealmMethodSecurityExpressionHandler defaultPermitRealmMethodSecurityExpressionHandler() {
        return new PermitRealmMethodSecurityExpressionHandler();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    protected SecurityFilterChain defaultSecurityFilterChain(
        HttpSecurity http,
        MultiSecurityRealmAuthenticationFilter multiSecurityRealmAuthenticationFilter
    ) throws Exception {
        log.info("Creating a default SecurityFilterChain with multi realms support...");

        http.addFilterBefore(multiSecurityRealmAuthenticationFilter, AnonymousAuthenticationFilter.class);
        http.authorizeHttpRequests(configurer -> configurer.anyRequest().authenticated());
        http.csrf(AbstractHttpConfigurer::disable);
        http.sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    @ConditionalOnMissingBean(value = {
        AuthenticationManager.class, AuthenticationProvider.class, UserDetailsService.class, AuthenticationManagerResolver.class
    }, type = "org.springframework.security.oauth2.jwt.JwtDecoder")
    protected AuthenticationManagerResolver<?> nullAuthenticationManagerResolver() {

        log.debug("registering a null AuthenticationManagerResolver to prevent spring boot form configuring a default"
            + " in-memory UserDetailsService (InMemoryUserDetailsManager)");
        
        return context -> null;
    }
}
