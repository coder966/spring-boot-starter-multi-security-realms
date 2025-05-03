package com.example.config;

import com.example.dto.AuthOtpStepRequest;
import com.example.dto.AuthUsernameAndPasswordStepRequest;
import com.example.entity.AdminUser;
import com.example.other.Constants;
import com.example.repo.AdminUserRepo;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.annotation.AuthenticationStep;
import net.coder966.spring.multisecurityrealms.annotation.SecurityRealm;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestBody;

@Slf4j
@SecurityRealm(
    name = "ADMIN_USER",
    authenticationEndpoint = "/admin-user/auth",
    firstStepName = Constants.StepNames.USERNAME_AND_PASSWORD,
    signingSecret = "${my-app.admin-realm-jwt-secret}",
    tokenExpirationDuration = "5m", // 5 minutes
    publicApis = {
        "/my-first-open-api",
        "/my-second-open-api"
    }
)
public class AdminUserSecurityRealm {

    @Autowired
    private AdminUserRepo adminUserRepo;

    @Transactional
    @AuthenticationStep(Constants.StepNames.USERNAME_AND_PASSWORD)
    public SecurityRealmAuthentication firstAuthenticationStep(@RequestBody AuthUsernameAndPasswordStepRequest request) {
        Optional<AdminUser> optionalUser = adminUserRepo.findByUsername(request.getUsername());
        if(optionalUser.isEmpty()){
            // Error description (the second argument) is optional
            throw new SecurityRealmAuthenticationException(Constants.ErrorCodes.BAD_CREDENTIALS, "Username or password is incorrect");
        }
        AdminUser user = optionalUser.get();

        // Don't remove me. I am an assertion to test that the code here runs inside a JPA session.
        log.info("user badges size {}", user.getBadges().size());

        // WARNING: FOR DEMO PURPOSE ONLY
        if(!user.getPassword().equals(request.getPassword())){
            // Since error description (the second argument to SecurityRealmAuthenticationException) is optional, we skipped it
            throw new SecurityRealmAuthenticationException(Constants.ErrorCodes.BAD_CREDENTIALS);
        }

        // TODO: send otp to mobile
        String otp = "1234"; // random
        user.setOtp(otp);
        user = adminUserRepo.save(user);

        // here we specify the next step name in the SecurityRealmAuthentication
        // if this is the last step, then don't specify the next step name, or send null
        return new SecurityRealmAuthentication(user.getUsername(), null, Constants.StepNames.OTP);
    }

    @Transactional
    @AuthenticationStep(Constants.StepNames.OTP)
    public SecurityRealmAuthentication otpAuthenticationStep(@RequestBody AuthOtpStepRequest request) {
        SecurityRealmAuthentication previousStepAuth = (SecurityRealmAuthentication) SecurityContextHolder.getContext().getAuthentication();

        String otp = request.getOtp();

        AdminUser user = adminUserRepo.findByUsername(previousStepAuth.getName()).get();

        // this might seem to be the incorrect place to update the counter and save
        // but I put it here to test @Transactional support
        user.setLoginCounter(user.getLoginCounter() + 1);
        adminUserRepo.save(user);


        if(!user.getOtp().equals(otp)){
            throw new SecurityRealmAuthenticationException(Constants.ErrorCodes.BAD_OTP, "OTP is incorrect");
        }

        // clear otp
        user.setOtp(otp);
        user = adminUserRepo.save(user);

        return new SecurityRealmAuthentication(user.getUsername(), null).addExtra("countBadges", user.getBadges().size());
    }
}
