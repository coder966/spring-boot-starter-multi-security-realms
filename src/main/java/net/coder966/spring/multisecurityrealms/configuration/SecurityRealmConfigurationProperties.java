package net.coder966.spring.multisecurityrealms.configuration;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security-realm")
public class SecurityRealmConfigurationProperties {

    private String signingSecret;
    private Duration fullyAuthenticatedTokenTtl;

    public String getSigningSecret() {
        return signingSecret;
    }

    public void setSigningSecret(String signingSecret) {
        this.signingSecret = signingSecret;
    }

    public Duration getFullyAuthenticatedTokenTtl() {
        return fullyAuthenticatedTokenTtl;
    }

    public void setFullyAuthenticatedTokenTtl(Duration fullyAuthenticatedTokenTtl) {
        this.fullyAuthenticatedTokenTtl = fullyAuthenticatedTokenTtl;
    }
}
