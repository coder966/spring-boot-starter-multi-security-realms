package net.coder966.spring.multisecurityrealms.config;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.entity.AdminUser;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.other.Constants.ErrorCodes;
import net.coder966.spring.multisecurityrealms.other.Constants.Headers;
import net.coder966.spring.multisecurityrealms.other.Constants.StepNames;
import net.coder966.spring.multisecurityrealms.repo.AdminUserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Configuration
public class AdminUserSecurityRealm extends SecurityRealm<AdminUser> {

    @Autowired
    private AdminUserRepo adminUserRepo;

    public AdminUserSecurityRealm() {
        super("ADMIN_USER", "/admin-user/login", "/admin-user/logout");
    }

    @Transactional
    @Override
    public SecurityRealmAuthentication<AdminUser> authenticate(
        HttpServletRequest request,
        String step,
        SecurityRealmAuthentication<AdminUser> previousStepAuth
    ) {
        if(step == null){ // first step
            String username = request.getHeader(Headers.USERNAME);
            String password = request.getHeader(Headers.PASSWORD);

            Optional<AdminUser> optionalUser = adminUserRepo.findByUsername(username);
            if(optionalUser.isEmpty()){
                throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
            }
            AdminUser user = optionalUser.get();


            // Don't remove me. I am an assertion to test that the code here runs inside a JPA session.
            log.info("user badges size {}", user.getBadges().size());

            // WARNING: FOR DEMO PURPOSE ONLY
            if(!user.getPassword().equals(password)){
                throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
            }

            // TODO: send otp to mobile
            String otp = "1234"; // random
            user.setOtp(otp);
            user = adminUserRepo.save(user);

            return new SecurityRealmAuthentication<>(user, user.getUsername(), null, StepNames.OTP);
        }else if(step.equals(StepNames.OTP)){
                String otp = request.getHeader(Headers.OTP);

                AdminUser user = previousStepAuth.getPrincipal();

                if(!user.getOtp().equals(otp)){
                    throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_OTP);
                }

                // clear otp
                user.setOtp(otp);
                user = adminUserRepo.save(user);

                return new SecurityRealmAuthentication<>(user, user.getUsername(), null);
        }

        throw new IllegalStateException("Should never happen");
    }

    @Override
    public List<RequestMatcher> getPublicApis() {
        return List.of(
            AntPathRequestMatcher.antMatcher("/admin-user/my-first-open-api"),
            AntPathRequestMatcher.antMatcher("/admin-user/my-second-open-api")
        );
    }
}
