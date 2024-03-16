package com.example.spring.multisecurityrealms.noop;

/**
 * We want to test for when the SecurityRealm implements an interface.
 * This is because Spring uses different proxy mechanisms when the bean implements an
 * interface. See: https://docs.spring.io/spring-framework/reference/core/aop/proxying.html
 */
public interface TestInterface {

    void foo();
}
