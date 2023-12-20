package net.coder966.spring.multisecurityrealms.provider;

import jakarta.servlet.http.HttpServletRequest;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuth;

public interface SecurityRealmAuthProvider<T> {

    SecurityRealmAuth<T> authenticate(SecurityRealmAuth<T> previousStepAuth, HttpServletRequest request);
}
