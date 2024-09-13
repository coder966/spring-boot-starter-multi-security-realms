# Changelog

## [0.1.2] - 2024-09-13

- Fix application not starting when `spring-boot-starter-actuator` is present in the classpath.

## [0.1.1] - 2024-07-12

- Internal enhancements.

## [0.1.0] - 2024-04-23

- Added `name` and `authorities` to the authentication response.
- Disable cookies by default.
- Fix partially authenticated users cannot access public apis from the same realm using their authentication token.
- Fix race condition where the order of realms discovery could lead to unstable behaviour.
- Improve tests.
- Improve docs.

## [0.0.9] - 2024-03-16

- Handle the scenario when the user attempts to authenticate while already fully authenticated.

## [0.0.8] - 2024-03-16

- Align `SecurityRealmAuthentication` and `SecurityRealmAnonymousAuthentication` with the built-in `Authentication` objects behaviours to increase
  compatibility.
- Register a null `AuthenticationManagerResolver` to prevent Spring Boot form configuring a default
  in-memory `UserDetailsService` (`InMemoryUserDetailsManager`).

## [0.0.7] - 2024-03-16

- added properties metadata.
- fix token in `Authorization` header not detected if the word `Bearer` is present.

## [0.0.6] - 2024-03-16

- fix `SecurityRealmAuthentication` unable to accept authorities set of subtypes of `GrantedAuthority`.
- fix auto configurations.

## [0.0.5] - 2024-03-16

- Annotation driven implementation. Refer to README file for examples.
- Added `permitRealm` security expression to check for the authenticated realm.
- Authentication is now stateless, using JWT tokens passed in the `Authorization` request header. This drops the logout api, and the `principal` in
  `SecurityRealmAuthentication`.
- Now the authentication endpoint returns all the details in the body (token, realm, error, next authentication step), instead of headers.
- Other minor enhancements and cleanups.
- Tests: enhancements.
- Docs: enhancements.

## [0.0.4] - 2023-12-30

- support joining JPA sessions in the authentication handler. Meaning annotating the authentication handler with `@Transactional` is now possible.

## [0.0.3] - 2023-12-23

- Create a default `SecurityFilterChain` and injects the multi realm support into it if the application does not already have one.
- Internal enhancements.

## [0.0.2] - 2023-12-23

- Support Spring Security 6.
- Minimum Java is now 17 instead of 21.
- Support any type of `SecurityContextRepository`. By default, this library creates a bean of `HttpSessionSecurityContextRepository` if you don't already have
  one.
- New feature: added the ability to define public apis per realm without the need to access and update the `SecurityFilterChain` manually.
  This is helpful if your application is huge, and you want to define public apis in segregated modules without the need to define them in a central place.
- Internal enhancements.

## [0.0.1] - 2023-12-23

First release

