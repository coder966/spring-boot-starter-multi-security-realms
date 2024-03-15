package net.coder966.spring.multisecurityrealms.reflection;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import lombok.SneakyThrows;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import org.springframework.security.core.Authentication;

public class AuthenticationStepInvoker {

    private final Object object;
    private final Method method;
    private final AuthenticationStepParameterType[] parameterTypes;

    public AuthenticationStepInvoker(Object object, Method method, AuthenticationStepParameterType[] parameterTypes) {
        this.object = object;
        this.method = method;
        this.parameterTypes = parameterTypes;
    }

    @SneakyThrows
    public SecurityRealmAuthentication invoke(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Object[] args = new Object[parameterTypes.length];
        for(int i = 0; i < parameterTypes.length; i++){
            AuthenticationStepParameterType parameterType = parameterTypes[i];
            switch(parameterType){
                case UNKNOWN -> args[i] = null;
                case REQUEST -> args[i] = request;
                case RESPONSE -> args[i] = response;
                case AUTHENTICATION -> args[i] = authentication;
                case BODY -> args[i] = null;
                case HEADERS -> args[i] = null;
            }
        }

        try{
            return (SecurityRealmAuthentication) method.invoke(object, args);
        }catch(InvocationTargetException invokeE){
            throw invokeE.getTargetException();
        }
    }
}
