package net.coder966.spring.multisecurityrealms.configuration;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security-realm")
public class SecurityRealmConfigurationProperties implements InitializingBean {

    private static final Logger log = LoggerFactory.getLogger(SecurityRealmConfigurationProperties.class);

    private String signingSecret;
    private Duration tokenExpirationDuration;

    @Override
    public void afterPropertiesSet() {
        if(signingSecret == null){
            log.warn(
                "Security Realm signing secret is not provided (security-realm.signing-secret). Will use auto generated secret."
                    + " Consider setting one because users authenticated on this app instance will not be recognized on other running instances."
            );
            signingSecret = UUID.randomUUID().toString() + UUID.randomUUID().toString();
        }

        if(tokenExpirationDuration == null){
            log.warn(
                "Security Realm token expiration duration is not provided (security-realm.token-expiration-duration). Will use 3 hours."
            );
            tokenExpirationDuration = Duration.of(3, ChronoUnit.HOURS);
        }
    }

    public String getSigningSecret() {
        return signingSecret;
    }

    public void setSigningSecret(String signingSecret) {
        this.signingSecret = signingSecret;
    }

    public Duration getTokenExpirationDuration() {
        return tokenExpirationDuration;
    }

    public void setTokenExpirationDuration(Duration tokenExpirationDuration) {
        this.tokenExpirationDuration = tokenExpirationDuration;
    }
}
