package net.coder966.spring.multisecurityrealms.configuration;

import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.filter.MultiSecurityRealmAuthenticationFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Slf4j
@AutoConfiguration
public class AutoConfigureMultiSecurityRealmsSupport {

    @ConditionalOnMissingBean(SecurityFilterChain.class)
    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity http, MultiSecurityRealmAuthenticationFilter multiSecurityRealmAuthenticationFilter)
        throws Exception {
        log.info("Creating a default SecurityFilterChain with multi realms support...");

        http.addFilterBefore(multiSecurityRealmAuthenticationFilter, AnonymousAuthenticationFilter.class);
        http.authorizeHttpRequests(configurer -> configurer.anyRequest().authenticated());
        http.csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

}
