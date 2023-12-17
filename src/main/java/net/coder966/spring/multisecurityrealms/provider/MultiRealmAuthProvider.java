package net.coder966.spring.multisecurityrealms.provider;

import jakarta.servlet.http.HttpServletRequest;
import net.coder966.spring.multisecurityrealms.model.MultiRealmAuth;

public interface MultiRealmAuthProvider<T> {

    MultiRealmAuth<T> authenticate(MultiRealmAuth<T> previousStepAuth, HttpServletRequest request);
}
