package net.coder966.spring.multisecurityrealms.reflection;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import lombok.SneakyThrows;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import org.springframework.security.core.Authentication;

public class AuthenticationStepInvoker {

    private final ObjectMapper objectMapper;
    private final Object object;
    private final Method method;
    private final AuthenticationStepParameterDetails[] parameterDetails;

    public AuthenticationStepInvoker(
        ObjectMapper objectMapper,
        Object object,
        Method method,
        AuthenticationStepParameterDetails[] parameterDetails
    ) {
        this.objectMapper = objectMapper;
        this.object = object;
        this.method = method;
        this.parameterDetails = parameterDetails;
    }

    @SneakyThrows
    public SecurityRealmAuthentication invoke(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Object[] args = new Object[parameterDetails.length];
        for(int i = 0; i < parameterDetails.length; i++){
            AuthenticationStepParameterDetails param = parameterDetails[i];
            switch(param.getType()){
                case UNKNOWN -> args[i] = null;
                case REQUEST -> args[i] = request;
                case RESPONSE -> args[i] = response;
                case AUTHENTICATION -> args[i] = authentication;
                case BODY -> args[i] = readBody(request, (Class<?>) param.getDetails("class"));
                case HEADER -> args[i] = readHeader(request, (Class<?>) param.getDetails("class"), (String) param.getDetails("headerName"));
            }
        }

        try{
            return (SecurityRealmAuthentication) method.invoke(object, args);
        }catch(InvocationTargetException invokeE){
            throw invokeE.getTargetException();
        }
    }

    @SneakyThrows
    private Object readBody(HttpServletRequest request, Class<?> type) {
        return objectMapper.readValue(request.getInputStream(), type);
    }

    private Object readHeader(HttpServletRequest request, Class<?> type, String headerName) {
        if(headerName != null && !headerName.isBlank()){
            return request.getHeader(headerName);
        }else if(type.isAssignableFrom(Map.class)){
            return Collections.list(request.getHeaderNames())
                .stream()
                .collect(Collectors.toMap(
                    Function.identity(),
                    h -> Collections.list(request.getHeaders(h))
                ));
        }
        return null;
    }
}
