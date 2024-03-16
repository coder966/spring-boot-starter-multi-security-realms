package com.example.spring.multisecurityrealms.noop;

import lombok.extern.slf4j.Slf4j;

/**
 * We want to test for when the SecurityRealm implements an interface. This is because Spring uses different proxy mechanisms when the bean implements an
 * interface. See: https://docs.spring.io/spring-framework/reference/core/aop/proxying.html
 */
@Slf4j
public class TestClass {

    void bar() {
        log.debug("bar");
    }
}
