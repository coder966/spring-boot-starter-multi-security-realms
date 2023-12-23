package net.coder966.spring.multisecurityrealms.autoconfigure;

import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.filter.MultiSecurityRealmAuthFilter;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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

    @ConditionalOnMissingBean(MultiSecurityRealmAuthFilter.class)
    @Bean
    public MultiSecurityRealmAuthFilter multiSecurityRealmAuthFilter(Set<SecurityRealm<?>> realms, SecurityContextRepository securityContextRepository) {
        log.info("Creating a default MultiSecurityRealmAuthFilter");
        return new MultiSecurityRealmAuthFilter(realms, securityContextRepository);
    }

    @ConditionalOnMissingBean(SecurityFilterChain.class)
    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http, MultiSecurityRealmAuthFilter multiSecurityRealmAuthFilter) throws Exception {
        log.info("Creating a default SecurityFilterChain");

        http.addFilterBefore(multiSecurityRealmAuthFilter, AnonymousAuthenticationFilter.class);

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
}
