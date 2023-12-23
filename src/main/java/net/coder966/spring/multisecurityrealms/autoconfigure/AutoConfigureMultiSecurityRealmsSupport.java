package net.coder966.spring.multisecurityrealms.autoconfigure;

import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.filter.MultiSecurityRealmAuthFilter;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

@Slf4j
@AutoConfiguration
public class AutoConfigureMultiSecurityRealmsSupport {

    @ConditionalOnMissingBean(SecurityContextRepository.class)
    @Bean
    public SecurityContextRepository httpSessionSecurityContextRepository() {
        log.info("Creating a default SecurityContextRepository of type HttpSessionSecurityContextRepository");
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public MultiSecurityRealmAuthFilter multiSecurityRealmAuthFilter(Set<SecurityRealm<?>> realms, SecurityContextRepository securityContextRepository) {
        return new MultiSecurityRealmAuthFilter(realms, securityContextRepository);
    }
}
