package net.coder966.spring.multisecurityrealms.provider;

import jakarta.servlet.http.HttpServletRequest;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;

public interface SecurityRealmFirstStepAuthenticationProvider<T> {

    SecurityRealmAuthentication<T> authenticate(HttpServletRequest request);
}
