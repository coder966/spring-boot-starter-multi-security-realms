package net.coder966.spring.multisecurityrealms.autoconfigure;

import java.util.Set;
import net.coder966.spring.multisecurityrealms.filter.MultiSecurityRealmAuthFilter;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AutoConfigureMultiSecurityRealmsSupport {

    @Bean
    public MultiSecurityRealmAuthFilter multiSecurityRealmAuthFilter(Set<SecurityRealm<?>> realms) {
        return new MultiSecurityRealmAuthFilter(realms);
    }
}
