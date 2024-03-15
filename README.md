# Spring Multi Security Realms

Support multiple security realms in a single Spring Boot application.

## What is a Security Realm

A realm is a scope of operations. A security realm is a security scope which defines protected resources and users in that realm.

For example, suppose you have a multi-tenant online e-store application. This application probably have these types of users:

- admin users / support users (realm)
- store owner users (realm)
- store customer users (realm)

These different user types are probably authenticated (login mechanism/flow/steps) and authorized (different protected APIs) differently.
Configuring this in Spring can be tricky and a bit complicated. You can even potentially introduce security bugs if you try to implement these features
manually.

## Why `spring-boot-starter-multi-security-realms`

This library allows you to easily and declaratively define these realms. It also brings extra features like:

- Multi steps authentication support (aka MFA). For example: username & password step, then OTP step, etc... You don't have to think about how to implement
  this, just use the built-in
  support.
- Ability to define public apis per realm without the need to access and update the `SecurityFilterChain` manually.
  This is helpful if your application is huge, and you want to define public apis in segregated modules without the need to define them in a central place.
- You still have full control and can define custom `SecurityFilterChain`s if you wish. By default,
  this library creates a default `SecurityFilterChain` and injects the multi realm support into it.

## Usage

### Requirements

- Spring Boot >= 3.x.x

### Installation

Maven:

```xml

<dependency>
    <groupId>net.coder966.spring</groupId>
    <artifactId>spring-boot-starter-multi-security-realms</artifactId>
    <version>0.0.4</version>
</dependency>
```

Gradle:

```groovy
implementation 'net.coder966.spring:spring-boot-starter-multi-security-realms:0.0.4'
```

## Usage

### Define security realms

To define a realm, simply create a bean of type `SecurityRealm`.
Here in this example, we define two realms (normal-user & admin-user).

#### NormalUserSecurityRealm.java
```java
@Slf4j
@SecurityRealm(
        name = "NORMAL_USER",
        authenticationEndpoint = "/normal-user/login",
        firstStepName = StepNames.USERNAME_AND_PASSWORD,
        publicApis = {
                "/normal-user/my-first-open-api",
                "/normal-user/my-second-open-api"
        }
)
public class NormalUserSecurityRealm {

    @Autowired
    private NormalUserRepo normalUserRepo;

    @Transactional
    @AuthenticationStep(StepNames.USERNAME_AND_PASSWORD)
    public SecurityRealmAuthentication firstAuthenticationStep(HttpServletRequest request) {
        String username = request.getHeader(Headers.USERNAME);
        String password = request.getHeader(Headers.PASSWORD);

        Optional<NormalUser> optionalUser = normalUserRepo.findByUsername(username);
        if (optionalUser.isEmpty()) {
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
        }
        NormalUser user = optionalUser.get();


        // WARNING: FOR DEMO PURPOSE ONLY
        if (!user.getPassword().equals(password)) {
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
        }

        // TODO: send otp to mobile
        String otp = "1234"; // random
        user.setOtp(otp);
        user = normalUserRepo.save(user);

        return new SecurityRealmAuthentication(user.getUsername(), null, StepNames.OTP);
    }

    @Transactional
    @AuthenticationStep(StepNames.OTP)
    public SecurityRealmAuthentication otpAuthenticationStep(HttpServletRequest request, SecurityRealmAuthentication previousStepAuth) {
        String otp = request.getHeader(Headers.OTP);

        NormalUser user = normalUserRepo.findByUsername(previousStepAuth.getName()).get();

        if (!user.getOtp().equals(otp)) {
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_OTP);
        }

        // clear otp
        user.setOtp(otp);
        user = normalUserRepo.save(user);

        return new SecurityRealmAuthentication(user.getUsername(), null);
    }
}
```

#### AdminUserSecurityRealm.java

```java
@Slf4j
@SecurityRealm(
        name = "ADMIN_USER",
        authenticationEndpoint = "/admin-user/login",
        firstStepName = StepNames.USERNAME_AND_PASSWORD,
        publicApis = {
                "/admin-user/my-first-open-api",
                "/admin-user/my-second-open-api"
        }
)
public class AdminUserSecurityRealm {

    @Autowired
    private AdminUserRepo adminUserRepo;

    @Transactional
    @AuthenticationStep(StepNames.USERNAME_AND_PASSWORD)
    public SecurityRealmAuthentication firstAuthenticationStep(HttpServletRequest request) {
        String username = request.getHeader(Headers.USERNAME);
        String password = request.getHeader(Headers.PASSWORD);

        Optional<AdminUser> optionalUser = adminUserRepo.findByUsername(username);
        if (optionalUser.isEmpty()) {
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
        }
        AdminUser user = optionalUser.get();


        // Don't remove me. I am an assertion to test that the code here runs inside a JPA session.
        log.info("user badges size {}", user.getBadges().size());

        // WARNING: FOR DEMO PURPOSE ONLY
        if (!user.getPassword().equals(password)) {
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
        }

        // TODO: send otp to mobile
        String otp = "1234"; // random
        user.setOtp(otp);
        user = adminUserRepo.save(user);

        return new SecurityRealmAuthentication(user.getUsername(), null, StepNames.OTP);
    }

    @Transactional
    @AuthenticationStep(StepNames.OTP)
    public SecurityRealmAuthentication otpAuthenticationStep(HttpServletRequest request, SecurityRealmAuthentication previousStepAuth) {
        String otp = request.getHeader(Headers.OTP);

        AdminUser user = adminUserRepo.findByUsername(previousStepAuth.getName()).get();

        if (!user.getOtp().equals(otp)) {
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_OTP);
        }

        // clear otp
        user.setOtp(otp);
        user = adminUserRepo.save(user);

        return new SecurityRealmAuthentication(user.getUsername(), null);
    }
}
```

### Client Application (Frontend)

- The client app should call the realm login api.
- You will receive a JWT token in the response body as a string.
- Store this token and pass in subsequent requests in the `Authorization` header.
- If the realm requires additional authentication steps from you (MFA),
  you will see the required authentication step name in the response header `X-Next-Auth-Step`. Render this step form and again submit to the same login api.
- In any case, if there is an error in the authentication (for example, bad credentials), you will receive the error in the response header `X-Auth-Error-Code`.

This image explains the whole authentication flow
![spring-boot-starter-multi-security-realms.png](docs/spring-boot-starter-multi-security-realms.png)

### Realm Protected APIs

To protect an api so that it can only be used by a certain realm users, you can use `@PreAuthorize("permitRealm('<realm-role-name>')")`.

Example:

```java
// adding this here, will apply it for all the endpoints in this controller
@PreAuthorize("permitRealm('ADMIN_USER')")
@RestController
public class AdminUserController {

    // OR it can be defined here at the method level
    @PreAuthorize("permitRealm('ADMIN_USER')")
    @GetMapping("/admin-user/my-name")
    public String myName() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication.getName(); // username
    }

}
```

## Tips

### I want to define my own `SecurityFilterChain`

If you want to define a custom `SecurityFilterChain` then you need to add this filter `MultiSecurityRealmAuthenticationFilter`
before `AnonymousAuthenticationFilter`.

```java

@Slf4j
@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    protected SecurityFilterChain globalSecurityFilterChain(
            HttpSecurity http,
            MultiSecurityRealmAuthenticationFilter multiSecurityRealmAuthenticationFilter // inject this filter
    ) throws Exception {

        // this is optional. If you don't have a custom SecurityFilterChain then you don't need to do all of this
        // A default SecurityFilterChain is configured out of the box.

        // add it before AnonymousAuthenticationFilter
        http.addFilterBefore(multiSecurityRealmAuthenticationFilter, AnonymousAuthenticationFilter.class);

        // the reset of your configuration ....

        return http.build();
    }

}
```

## License

```txt
Copyright 2023 Khalid H. Alharisi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```