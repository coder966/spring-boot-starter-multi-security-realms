package net.coder966.spring.multisecurityrealms;

import net.coder966.spring.multisecurityrealms.model.Realm;
import org.springframework.stereotype.Component;

@Component
public class MultiRealmSecurityConfigurer {

    public <T> Realm<T> addRealm(String rolePrefix, String loginUrl, String logoutUrl) {
        Realm<T> realm = new Realm<>(rolePrefix, loginUrl, logoutUrl);
        MultiRealmAuthFilter.realmsByLoginUrl.put(realm.getLoginUrl(), realm);
        MultiRealmAuthFilter.realmsByLogoutUrl.put(realm.getLogoutUrl(), realm);
        return realm;
    }
}
