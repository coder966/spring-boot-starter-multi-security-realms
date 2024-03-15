package net.coder966.spring.multisecurityrealms.config;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.annotation.AuthenticationStep;
import net.coder966.spring.multisecurityrealms.annotation.SecurityRealm;
import net.coder966.spring.multisecurityrealms.entity.AdminUser;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.other.Constants.ErrorCodes;
import net.coder966.spring.multisecurityrealms.other.Constants.Headers;
import net.coder966.spring.multisecurityrealms.other.Constants.StepNames;
import net.coder966.spring.multisecurityrealms.repo.AdminUserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@SecurityRealm(
    name = "ADMIN_USER",
    authenticationEndpoint = "/admin-user/auth",
    firstStepName = StepNames.USERNAME_AND_PASSWORD,
    publicApis = {
        "/admin-user/my-first-open-api",
        "/admin-user/my-second-open-api"
    }
)
public class AdminUserSecurityRealm {

    @Autowired
    private AdminUserRepo adminUserRepo;

    @Transactional
    @AuthenticationStep(StepNames.USERNAME_AND_PASSWORD)
    public SecurityRealmAuthentication firstAuthenticationStep(HttpServletRequest request) {
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

        // here we specify the next step name in the SecurityRealmAuthentication
        // if this is the last step, then don't specify the next step name, or send null
        return new SecurityRealmAuthentication(user.getUsername(), null, StepNames.OTP);
    }

    @Transactional
    @AuthenticationStep(StepNames.OTP)
    public SecurityRealmAuthentication otpAuthenticationStep(HttpServletRequest request, SecurityRealmAuthentication previousStepAuth) {
        String otp = request.getHeader(Headers.OTP);

        AdminUser user = adminUserRepo.findByUsername(previousStepAuth.getName()).get();

        if(!user.getOtp().equals(otp)){
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_OTP);
        }

        // clear otp
        user.setOtp(otp);
        user = adminUserRepo.save(user);

        return new SecurityRealmAuthentication(user.getUsername(), null);
    }
}
