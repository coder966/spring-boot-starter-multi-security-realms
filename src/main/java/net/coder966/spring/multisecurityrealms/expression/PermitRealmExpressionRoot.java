package net.coder966.spring.multisecurityrealms.expression;

import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;

public class PermitRealmExpressionRoot extends SecurityExpressionRoot {

    public PermitRealmExpressionRoot(Authentication authentication) {
        super(authentication);
    }

    public boolean permitRealm(String[] realmName) {
        Authentication auth = getAuthentication();

        if(!(auth instanceof SecurityRealmAuthentication)){
            return false;
        }

        if(realmName == null){
            return false;
        }

        String actualRealmName = ((SecurityRealmAuthentication) auth).getRealmName();

        boolean permitted = false;
        for(String expected : realmName){
            if(expected.equals(actualRealmName)){
                permitted = true;
                break;
            }
        }

        return permitted;
    }

    public boolean permitRealm(String realmName) {
        return permitRealm(new String[]{realmName});
    }
}
