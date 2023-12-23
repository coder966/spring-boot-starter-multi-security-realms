package net.coder966.spring.multisecurityrealms.provider;

import jakarta.servlet.http.HttpServletRequest;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;

public interface SecurityRealmAuthenticationProvider<T> {

    SecurityRealmAuthentication<T> authenticate(SecurityRealmAuthentication<T> previousStepAuth, HttpServletRequest request);
}
