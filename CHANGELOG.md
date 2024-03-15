# Changelog

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

