package net.coder966.spring.multisecurityrealms.config;

import jakarta.annotation.PostConstruct;
import java.util.Optional;
import lombok.AllArgsConstructor;
import net.coder966.spring.multisecurityrealms.MultiRealmSecurityConfigurer;
import net.coder966.spring.multisecurityrealms.entity.AdminUser;
import net.coder966.spring.multisecurityrealms.entity.NormalUser;
import net.coder966.spring.multisecurityrealms.exception.MultiRealmAuthException;
import net.coder966.spring.multisecurityrealms.model.MultiRealmAuth;
import net.coder966.spring.multisecurityrealms.other.Constants.ErrorCodes;
import net.coder966.spring.multisecurityrealms.other.Constants.Headers;
import net.coder966.spring.multisecurityrealms.other.Constants.StepNames;
import net.coder966.spring.multisecurityrealms.repo.AdminUserRepo;
import net.coder966.spring.multisecurityrealms.repo.NormalUserRepo;
import org.springframework.context.annotation.Configuration;

@AllArgsConstructor
@Configuration
public class TestConfig {

    private final MultiRealmSecurityConfigurer configurer;
    private final NormalUserRepo normalUserRepo;
    private final AdminUserRepo adminUserRepo;

    @PostConstruct
    public void configureNormalUserRealm() {
        configurer.<NormalUser>addRealm(
                "NORMAL_USER",
                "/normal-user/login",
                "/normal-user/logout"
            )
            .setFirstAuthStep(request -> {
                // WARNING: FOR DEMO PURPOSE ONLY

                String username = request.getHeader(Headers.USERNAME);
                String password = request.getHeader(Headers.PASSWORD);

                Optional<NormalUser> optionalUser = normalUserRepo.findByUsername(username);
                if(optionalUser.isEmpty()){
                    throw new MultiRealmAuthException(ErrorCodes.BAD_CREDENTIALS);
                }
                NormalUser user = optionalUser.get();


                // WARNING: FOR DEMO PURPOSE ONLY
                if(!user.getPassword().equals(password)){
                    throw new MultiRealmAuthException(ErrorCodes.BAD_CREDENTIALS);
                }

                // TODO: send otp to mobile
                String otp = "1234"; // random
                user.setOtp(otp);
                user = normalUserRepo.save(user);

                return new MultiRealmAuth<>(user, user.getUsername(), null, StepNames.OTP);
            })
            .addAuthStep(StepNames.OTP, (previousStepAuth, request) -> {
                String otp = request.getHeader(Headers.OTP);

                NormalUser user = previousStepAuth.getPrincipal();

                if(!user.getOtp().equals(otp)){
                    throw new MultiRealmAuthException(ErrorCodes.BAD_OTP);
                }

                // clear otp
                user.setOtp(otp);
                user = normalUserRepo.save(user);

                return new MultiRealmAuth<>(user, user.getUsername(), null);
            });
    }

    @PostConstruct
    public void configureAdminUserRealm() {
        configurer.<AdminUser>addRealm(
                "ADMIN_USER",
                "/admin-user/login",
                "/admin-user/logout"
            )
            .setFirstAuthStep(request -> {
                // WARNING: FOR DEMO PURPOSE ONLY

                String username = request.getHeader(Headers.USERNAME);
                String password = request.getHeader(Headers.PASSWORD);

                Optional<AdminUser> optionalUser = adminUserRepo.findByUsername(username);
                if(optionalUser.isEmpty()){
                    throw new MultiRealmAuthException(ErrorCodes.BAD_CREDENTIALS);
                }
                AdminUser user = optionalUser.get();


                // WARNING: FOR DEMO PURPOSE ONLY
                if(!user.getPassword().equals(password)){
                    throw new MultiRealmAuthException(ErrorCodes.BAD_CREDENTIALS);
                }

                // TODO: send otp to mobile
                String otp = "1234"; // random
                user.setOtp(otp);
                user = adminUserRepo.save(user);

                return new MultiRealmAuth<>(user, user.getUsername(), null, StepNames.OTP);
            })
            .addAuthStep(StepNames.OTP, (previousStepAuth, request) -> {
                String otp = request.getHeader(Headers.OTP);

                AdminUser user = previousStepAuth.getPrincipal();

                if(!user.getOtp().equals(otp)){
                    throw new MultiRealmAuthException(ErrorCodes.BAD_OTP);
                }

                // clear otp
                user.setOtp(otp);
                user = adminUserRepo.save(user);

                return new MultiRealmAuth<>(user, user.getUsername(), null);
            });
    }
}
