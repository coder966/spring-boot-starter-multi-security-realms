# Changelog

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

