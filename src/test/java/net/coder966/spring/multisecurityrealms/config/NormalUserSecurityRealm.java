package net.coder966.spring.multisecurityrealms.config;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import net.coder966.spring.multisecurityrealms.entity.NormalUser;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.other.Constants.ErrorCodes;
import net.coder966.spring.multisecurityrealms.other.Constants.Headers;
import net.coder966.spring.multisecurityrealms.other.Constants.StepNames;
import net.coder966.spring.multisecurityrealms.repo.NormalUserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Slf4j
@Configuration
public class NormalUserSecurityRealm extends SecurityRealm {

    @Autowired
    private NormalUserRepo normalUserRepo;

    public NormalUserSecurityRealm() {
        super("NORMAL_USER", "/normal-user/login");
    }

    @Override
    public SecurityRealmAuthentication authenticate(
        HttpServletRequest request,
        String step,
        SecurityRealmAuthentication previousStepAuth
    ) {
        if(step == null){
            // WARNING: FOR DEMO PURPOSE ONLY

            String username = request.getHeader(Headers.USERNAME);
            String password = request.getHeader(Headers.PASSWORD);

            Optional<NormalUser> optionalUser = normalUserRepo.findByUsername(username);
            if(optionalUser.isEmpty()){
                throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
            }
            NormalUser user = optionalUser.get();


            // WARNING: FOR DEMO PURPOSE ONLY
            if(!user.getPassword().equals(password)){
                throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
            }

            // TODO: send otp to mobile
            String otp = "1234"; // random
            user.setOtp(otp);
            user = normalUserRepo.save(user);

            return new SecurityRealmAuthentication(user.getUsername(), null, StepNames.OTP);
        }else if(step.equals(StepNames.OTP)){
            String otp = request.getHeader(Headers.OTP);

            NormalUser user = normalUserRepo.findByUsername(previousStepAuth.getName()).get();

            if(!user.getOtp().equals(otp)){
                throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_OTP);
            }

            // clear otp
            user.setOtp(otp);
            user = normalUserRepo.save(user);

            return new SecurityRealmAuthentication(user.getUsername(), null);
        }

        throw new IllegalStateException("Should never happen");
    }

    @Override
    public List<RequestMatcher> getPublicApis() {
        return List.of(
            AntPathRequestMatcher.antMatcher("/normal-user/my-first-open-api"),
            AntPathRequestMatcher.antMatcher("/normal-user/my-second-open-api")
        );
    }
}
