package net.coder966.spring.multisecurityrealms.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.stereotype.Component;

/**
 * Indicates that the annotated controller method (or class) can be accessed without authentication.
 *
 * <p><strong>Usage Example:</strong></p>
 * <pre>{@code
 * @RestController
 * @RequestMapping("/lookup")
 * public class PublicController {
 *
 *     @AnonymousAccess
 *     @GetMapping("/cities")
 *     public List<String> getCities() {
 *         return "This endpoint is open to everyone.";
 *     }
 * }
 * }</pre>
 *
 */
@Component
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface AnonymousAccess {
}
