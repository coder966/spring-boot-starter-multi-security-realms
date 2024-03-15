package net.coder966.spring.multisecurityrealms.reflection;

import java.util.HashMap;
import java.util.Map;

public class AuthenticationStepParameterDetails {

    private final AuthenticationStepParameterType type;
    private final Map<String, Object> details = new HashMap<>();

    public AuthenticationStepParameterDetails(AuthenticationStepParameterType type) {
        this.type = type;
    }

    public AuthenticationStepParameterDetails withDetails(String key, Object value) {
        details.put(key, value);
        return this;
    }

    public AuthenticationStepParameterType getType() {
        return type;
    }

    public Object getDetails(String key) {
        return details.get(key);
    }
}
