package net.coder966.spring.multisecurityrealms.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.advice.SecurityRealmControllerAdvice;
import net.coder966.spring.multisecurityrealms.converter.AuthenticationTokenConverter;
import net.coder966.spring.multisecurityrealms.expression.PermitRealmMethodSecurityExpressionHandler;
import net.coder966.spring.multisecurityrealms.filter.MultiSecurityRealmAuthenticationFilter;
import net.coder966.spring.multisecurityrealms.reflection.SecurityRealmScanner;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Slf4j
@AutoConfiguration
public class AutoConfigureMultiSecurityRealmsSupport {

    @Bean
    @ConditionalOnMissingBean(SecurityRealmConfigurationProperties.class)
    public SecurityRealmConfigurationProperties defaultSecurityRealmConfigurationProperties() {
        return new SecurityRealmConfigurationProperties();
    }

    @Bean
    public AuthenticationTokenConverter defaultAuthenticationTokenConverter(SecurityRealmConfigurationProperties properties) {
        return new AuthenticationTokenConverter(properties);
    }

    @Bean
    public SecurityRealmControllerAdvice defaultSecurityRealmControllerAdvice() {
        return new SecurityRealmControllerAdvice();
    }


    @Bean
    public SecurityRealmScanner defaultSecurityRealmScanner(ApplicationContext context) {
        return new SecurityRealmScanner(context);
    }

    @Bean
    public MultiSecurityRealmAuthenticationFilter defaultMultiSecurityRealmAuthenticationFilter(
        SecurityRealmScanner securityRealmScanner,
        ObjectMapper objectMapper
    ) {
        return new MultiSecurityRealmAuthenticationFilter(
            securityRealmScanner,
            objectMapper
        );
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
    @ConditionalOnMissingBean(value = {AuthenticationManager.class, AuthenticationProvider.class, UserDetailsService.class,
        AuthenticationManagerResolver.class}, type = "org.springframework.security.oauth2.jwt.JwtDecoder")
    protected AuthenticationManagerResolver<?> nullAuthenticationManagerResolver() {
        log.debug("registering a null AuthenticationManagerResolver to prevent spring boot form configuring a default"
            + " in-memory UserDetailsService (InMemoryUserDetailsManager)");
        return context -> null;
    }
}
