package com.example.spring.multisecurityrealms.config;

import com.example.spring.multisecurityrealms.dto.AuthOtpStepRequest;
import com.example.spring.multisecurityrealms.dto.AuthUsernameAndPasswordStepRequest;
import com.example.spring.multisecurityrealms.entity.NormalUser;
import com.example.spring.multisecurityrealms.noop.TestClass;
import com.example.spring.multisecurityrealms.noop.TestInterface;
import com.example.spring.multisecurityrealms.other.Constants.ErrorCodes;
import com.example.spring.multisecurityrealms.other.Constants.StepNames;
import com.example.spring.multisecurityrealms.repo.NormalUserRepo;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.annotation.AuthenticationStep;
import net.coder966.spring.multisecurityrealms.annotation.SecurityRealm;
import net.coder966.spring.multisecurityrealms.authentication.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestBody;

@Slf4j
@SecurityRealm(
    name = "NORMAL_USER",
    authenticationEndpoint = "/normal-user/auth",
    firstStepName = StepNames.USERNAME_AND_PASSWORD,
    publicApis = {
        "/my-third-open-api",
        "/my-forth-open-api"
    }
)
public class NormalUserSecurityRealm extends TestClass implements TestInterface {

    @Autowired
    private NormalUserRepo normalUserRepo;

    @Transactional
    @AuthenticationStep(StepNames.USERNAME_AND_PASSWORD)
    public SecurityRealmAuthentication firstAuthenticationStep(@RequestBody AuthUsernameAndPasswordStepRequest request) {
        Optional<NormalUser> optionalUser = normalUserRepo.findByUsername(request.getUsername());
        if(optionalUser.isEmpty()){
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
        }
        NormalUser user = optionalUser.get();


        // WARNING: FOR DEMO PURPOSE ONLY
        if(!user.getPassword().equals(request.getPassword())){
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
        }

        // TODO: send otp to mobile
        String otp = "1234"; // random
        user.setOtp(otp);
        user = normalUserRepo.save(user);

        // here we specify the next step name in the SecurityRealmAuthentication
        // if this is the last step, then don't specify the next step name, or send null
        return new SecurityRealmAuthentication(user.getUsername(), null, StepNames.OTP);
    }

    @Transactional
    @AuthenticationStep(StepNames.OTP)
    public SecurityRealmAuthentication otpAuthenticationStep(@RequestBody AuthOtpStepRequest request, SecurityRealmAuthentication previousStepAuth) {
        String otp = request.getOtp();

        NormalUser user = normalUserRepo.findByUsername(previousStepAuth.getName()).get();

        if(!user.getOtp().equals(otp)){
            throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_OTP);
        }

        // clear otp
        user.setOtp(otp);
        user = normalUserRepo.save(user);

        return new SecurityRealmAuthentication(user.getUsername(), null);
    }

    @Override
    public void foo() {
        log.debug("foo");
    }
}
