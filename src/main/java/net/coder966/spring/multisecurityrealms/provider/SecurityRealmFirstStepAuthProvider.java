package net.coder966.spring.multisecurityrealms.provider;

import jakarta.servlet.http.HttpServletRequest;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuth;

public interface SecurityRealmFirstStepAuthProvider<T> {

    SecurityRealmAuth<T> authenticate(HttpServletRequest request);
}
