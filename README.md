# Spring Multi Security Realms

[![Maven Central](https://img.shields.io/maven-central/v/net.coder966.spring/spring-boot-starter-multi-security-realms)](https://central.sonatype.com/artifact/net.coder966.spring/spring-boot-starter-multi-security-realms)

Support multiple security realms in a single Spring Boot application.

## What is a Security Realm

A realm is a scope of operations. A security realm is a security scope which defines protected resources and users in that realm.

For example, suppose you have a multi-tenant online e-store application. This application probably support these types of users:

- admin users / helpdesk users (realm)
- store owner users (realm)
- store customer users (realm)

These different user types are probably authenticated (login mechanism/flow/steps) and authorized (protected APIs) differently.
Configuring this in Spring can be tricky and a bit complicated. You can even potentially introduce security bugs if you try to implement these features
manually.

## Why `spring-boot-starter-multi-security-realms`

This library allows you to easily and declaratively define these realms. It also brings extra features like:

- Multi-steps authentication support (aka Multi-Factor Authentication MFA). For example: username & password step, then OTP step, etc... You don't have to think
  about how to implement this, just use the built-in support.
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
    <version>0.3.1</version>
</dependency>
```

Gradle:

```groovy
implementation 'net.coder966.spring:spring-boot-starter-multi-security-realms:0.3.1'
```

## Usage

### Define security realms

To define a realm, simply create a Spring component and annotate it with `@SecurityRealm`.
Here in this example, we define two realms (normal-user & admin-user).

#### NormalUserSecurityRealm.java
```java
@Slf4j
@SecurityRealm(
        name = "NORMAL_USER",
        authenticationEndpoint = "/normal-user/auth",
        firstStepName = StepNames.USERNAME_AND_PASSWORD,
        //    signingSecret = "", // not specified, will use default configured under security-realm.*
        //    tokenExpirationDuration = "", // not specified, will use default configured under security-realm.*
        publicApis = {
                "/my-third-open-api",
                "/my-forth-open-api"
        }
)
public class NormalUserSecurityRealm {

    @Autowired
    private NormalUserRepo normalUserRepo;

    @Transactional
    @AuthenticationStep(StepNames.USERNAME_AND_PASSWORD)
    public SecurityRealmAuthentication firstAuthenticationStep(@RequestBody AuthUsernameAndPasswordStepRequest request) {
        Optional<NormalUser> optionalUser = normalUserRepo.findByUsername(request.getUsername());
        if (optionalUser.isEmpty()) {
            // Error description (the second argument) is optional
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS, "Username or password is incorrect");
        }
        NormalUser user = optionalUser.get();

        // WARNING: FOR DEMO PURPOSE ONLY
        if (!user.getPassword().equals(request.getPassword())) {
            // Since error description (the second argument to SecurityRealmAuthenticationException) is optional, we skipped it
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
        }

        // TODO: send otp to mobile
        String otp = "1234"; // random
        user.setOtp(otp);
        user = normalUserRepo.save(user);

        // here we specify the next step name in the SecurityRealmAuthentication
        // if this is the last step, then don't specify the next step name, or send null
        return new SecurityRealmAuthentication(user.getUsername(), null, StepNames.OTP);
    }

    @Transactional
    @AuthenticationStep(StepNames.OTP)
    public SecurityRealmAuthentication otpAuthenticationStep(@RequestBody AuthOtpStepRequest request) {
        SecurityRealmAuthentication previousStepAuth = (SecurityRealmAuthentication) SecurityContextHolder.getContext().getAuthentication();

        String otp = request.getOtp();

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
        authenticationEndpoint = "/admin-user/auth",
        firstStepName = StepNames.USERNAME_AND_PASSWORD,
        signingSecret = "${my-app.admin-realm-jwt-secret}",
        tokenExpirationDuration = "5m", // 5 minutes
        publicApis = {
                "/my-first-open-api",
                "/my-second-open-api"
        }
)
public class AdminUserSecurityRealm {

    @Autowired
    private AdminUserRepo adminUserRepo;

    @Transactional
    @AuthenticationStep(StepNames.USERNAME_AND_PASSWORD)
    public SecurityRealmAuthentication firstAuthenticationStep(@RequestBody AuthUsernameAndPasswordStepRequest request) {
        Optional<AdminUser> optionalUser = adminUserRepo.findByUsername(request.getUsername());
        if (optionalUser.isEmpty()) {
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
        }
        AdminUser user = optionalUser.get();

        // WARNING: FOR DEMO PURPOSE ONLY
        if (!user.getPassword().equals(request.getPassword())) {
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
        }

        // TODO: send otp to mobile
        String otp = "1234"; // random
        user.setOtp(otp);
        user = adminUserRepo.save(user);

        // here we specify the next step name in the SecurityRealmAuthentication
        // if this is the last step, then don't specify the next step name, or send null
        return new SecurityRealmAuthentication(user.getUsername(), null, StepNames.OTP);
    }

    @Transactional
    @AuthenticationStep(StepNames.OTP)
    public SecurityRealmAuthentication otpAuthenticationStep(@RequestBody AuthOtpStepRequest request) {
        SecurityRealmAuthentication previousStepAuth = (SecurityRealmAuthentication) SecurityContextHolder.getContext().getAuthentication();

        String otp = request.getOtp();

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

- The client app should call the realm authentication endpoint.
- You will receive an access token in the response body field `token`, store it and pass it to all subsequent requests in the `Authorization` header.
- If the realm requires additional authentication steps from you (MFA),
  you will see the required authentication step name in the response body field `nextAuthenticationStep`. Redirect the user or
  render this step form and again submit to the same authentication endpoint.
- In any case, if there is an error in the authentication (for example, bad credentials, bad otp, etc...), you will receive the error in the response body field
  `error`, and the HTTP status will be `400`.

#### Sample Response (success)

Rendered username+password form and submitted, and got:

```json
{
    "name": "khalid",
    "authorities": [],
    "nextAuthenticationStep": "OTP",
    "realm": "ADMIN_USER",
    "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJraGFsaWQiLCJyZWFsbSI6IkFETUlOX1VTRVIiLCJuZXh0QXV0aGVudGljYXRpb25TdGVwIjoiT1RQIiwiYXV0aG9yaXRpZXMiOltdLCJleHAiOjE3NDYxMzcwMDN9.T-C2LO5DmawUXG6XuhyqTH9hxc8VIE4nF1u2_u2a_Xqw4SRbMpJ7Aq--AwcEA-jzSj6Si9_O1V21P-mkKU31FQ",
    "tokenType": "Bearer",
    "expiresInSeconds": 300,
    "extras": {}
}
```

Rendered OTP form and submitted again, and got:

```json
{
    "name": "khalid",
    "authorities": [],
    "nextAuthenticationStep": null,
    "realm": "ADMIN_USER",
    "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJraGFsaWQiLCJyZWFsbSI6IkFETUlOX1VTRVIiLCJuZXh0QXV0aGVudGljYXRpb25TdGVwIjpudWxsLCJhdXRob3JpdGllcyI6W10sImV4cCI6MTc0NjEzNzA3OX0.OYwacoHwO6iS-t3JXe0Fw0xKMIjBTypaasNJIghrdPW9RZMGzaghxCw1GYSz5p6E7c8dIubLKkvRf-QAhGIxVA",
    "tokenType": "Bearer",
    "expiresInSeconds": 300,
    "extras": {}
}
```

#### Sample Response (error) status = 400

```json
{
    "error": "BAD_CREDENTIALS",
    "errorDescription": "Username or password is incorrect"
}
```

#### Full Sample Client (React App NextJS)

```tsx
'use client'

import {RruForm, RruTextInput} from "react-rich-ui";
import validationSchemas from "@/utils/validationSchemas";
import * as yup from "yup";
import React, {useEffect} from "react";
import Image from "next/image";
import LoadingService from "@/service/LoadingService";
import {useRouter} from "next/navigation";
import AuthApis, {AuthenticationStep} from "@/client/AuthApis";
import DialogService from "@/service/DialogService";

export default function Login() {
    const router = useRouter();
    const [step, setStep] = React.useState<AuthenticationStep>('USERNAME_PASSWORD');

    useEffect(() => {
        if (!step) {
            router.replace("/protected");
        }
    }, [step]);

    const usernamePasswordFormSchema = yup.object().shape({
        username: validationSchemas.username(true),
        password: validationSchemas.password(true),
    })

    const otpFormSchema = yup.object().shape({
        otp: validationSchemas.otp(true),
    })

    const onSubmitUsernamePassword = async (form) => {
        try {
            LoadingService.start();
            const res = await AuthApis.usernamePassword(form.username, form.password);
            localStorage.setItem("token", res.token);
            setStep(res.nextAuthenticationStep);
        } catch (error) {
            DialogService.showError(error);
        } finally {
            LoadingService.stop();
        }
    }

    const onSubmitOtp = async (form) => {
        try {
            LoadingService.start();
            const res = await AuthApis.otp(form.otp);
            localStorage.setItem("token", res.token);
            setStep(res.nextAuthenticationStep);
        } catch (error) {
            DialogService.showError(error);
        } finally {
            LoadingService.stop();
        }
    }

    return (
            <div className="container d-flex align-items-center justify-content-center min-vh-100">
                <div className="w-100" style={{maxWidth: '400px'}}>

                    <Image src={'/images/logo.svg'} width={70} height={70} className="ms-auto me-auto mb-4" alt={'logo'}/>

                    {step === 'USERNAME_PASSWORD' && (
                            <RruForm onSubmit={onSubmitUsernamePassword} yupValidationSchema={usernamePasswordFormSchema}>
                                <div className="mb-3">
                                    <RruTextInput name={'username'} label={'Username'} autoComplete={'username'} requiredAsterisk={true}/>
                                </div>
                                <div className="mb-3">
                                    <RruTextInput name={'password'} label={'Password'} autoComplete={'password'} requiredAsterisk={true}/>
                                </div>
                                <button type="submit" className="btn btn-primary w-100">Login</button>
                            </RruForm>
                    )}

                    {step === 'OTP' && (
                            <RruForm onSubmit={onSubmitOtp} yupValidationSchema={otpFormSchema}>
                                <div className="mb-3">
                                    <RruTextInput name={'otp'} label={'OTP'} autoComplete={'otp'} requiredAsterisk={true} maxLength={4}/>
                                </div>
                                <button type="submit" className="btn btn-primary w-100">Login</button>
                            </RruForm>
                    )}

                </div>
            </div>
    );
}
```

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

### Configure JWT secret and TTL

You can specify a different signing secret and a TTL for each realm separately (using the `@SecurityRealm` annotation).
You can also specify global values using the configuration properties:

- `security-realm.signing-secret`
- `security-realm.token-expiration-duration`

### Pass extra data to the response in success authentication

You can put extra data (key-value pairs) in the authentication object, which will appear in the authentication response under the key `extras`.

#### Example code

```java

@AuthenticationStep(Constants.StepNames.OTP)
public SecurityRealmAuthentication otpAuthenticationStep(@RequestBody AuthOtpStepRequest request) {
    SecurityRealmAuthentication previousStepAuth = (SecurityRealmAuthentication) SecurityContextHolder.getContext().getAuthentication();

    // code

    return new SecurityRealmAuthentication(user.getUsername(), null).addExtra("countBadges", user.getBadges().size());
}
```

#### Example response

```json
{
    "realm": "ADMIN_USER",
    "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJyZWFsbSI6IkFETUlOX1VTRVIiLCJzdWIiOiJraGFsaWQiLCJhdXRob3JpdGllcyI6W10sIm5leHRBdXRoZW50aWNhdGlvblN0ZXAiOm51bGwsImV4cCI6MTc0NjI5MjU4MX0.JWxJKEU5mOsDA4czZV1ZdpxqLpNefrkeVmc-wmb3r4YmT5pVS3EBJi8jW-0ohne7q8VsQ5WYx4e3vW0OIgw4ig",
    "tokenType": "Bearer",
    "expiresInSeconds": 300,
    "name": "khalid",
    "authorities": [],
    "nextAuthenticationStep": null,
    "extras": {
        "countBadges": 0
    }
}
```

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


        // session should be disabled
        http.sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        // disable csrf, because JWT token is not stored in the cookies, so CSRF protection is not needed
        // you can still enable it, but you have to support it in your client application (frontend)
        http.csrf(AbstractHttpConfigurer::disable);


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