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
     * The TTL (Time-To-Live) after which the token <b>for the fully authenticated user (no further steps)</b> will expire.
     * This is a duration expression, for example, "3m" for 3 minutes or "7h" for 7 hours etc...
     * If not specified, will use the default specified under the configuration property <pre>security-realm.fully-authenticated-token-ttl</pre>
     */
    String fullyAuthenticatedTokenTtl() default "";
}
