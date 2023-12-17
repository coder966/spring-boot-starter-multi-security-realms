package net.coder966.spring.multisecurityrealms.provider;

import jakarta.servlet.http.HttpServletRequest;
import net.coder966.spring.multisecurityrealms.model.MultiRealmAuth;

public interface MultiRealmFirstStepAuthProvider<T> {

    MultiRealmAuth<T> authenticate(HttpServletRequest request);
}
