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

    String[] publicApis() default {};
}
