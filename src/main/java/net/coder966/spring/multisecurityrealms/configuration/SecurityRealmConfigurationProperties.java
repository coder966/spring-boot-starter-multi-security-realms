package net.coder966.spring.multisecurityrealms.configuration;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "security-realm")
public class SecurityRealmConfigurationProperties implements InitializingBean {

    private String signingSecret;
    private Duration tokenExpirationDuration;

    @Override
    public void afterPropertiesSet() {
        if(signingSecret == null){
            throw new IllegalArgumentException(
                "You must specify the signing secret in your application properties file. Key: security-realm.signing-secret");
        }

        if(tokenExpirationDuration == null){
            tokenExpirationDuration = Duration.of(3, ChronoUnit.HOURS);
        }
    }
}
