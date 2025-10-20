package net.coder966.spring.multisecurityrealms.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.stereotype.Component;

@Component
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface SecurityRealm {

    String name();

    String authenticationEndpoint();

    String firstStepName();

    String signingSecret() default "";

    /**
     * @return Duration expression, for example, "3m" for 3 minutes or "7h" for 7 hours etc...
     */
    String tokenExpirationDuration() default "";
}
