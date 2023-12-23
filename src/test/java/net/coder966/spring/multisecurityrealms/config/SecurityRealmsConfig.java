package net.coder966.spring.multisecurityrealms.config;

import java.util.Optional;
import lombok.AllArgsConstructor;
import net.coder966.spring.multisecurityrealms.entity.AdminUser;
import net.coder966.spring.multisecurityrealms.entity.NormalUser;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthException;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuth;
import net.coder966.spring.multisecurityrealms.other.Constants.ErrorCodes;
import net.coder966.spring.multisecurityrealms.other.Constants.Headers;
import net.coder966.spring.multisecurityrealms.other.Constants.StepNames;
import net.coder966.spring.multisecurityrealms.repo.AdminUserRepo;
import net.coder966.spring.multisecurityrealms.repo.NormalUserRepo;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@AllArgsConstructor
@Configuration
public class SecurityRealmsConfig {

    private final NormalUserRepo normalUserRepo;
    private final AdminUserRepo adminUserRepo;

    @Bean
    public SecurityRealm<NormalUser> configureNormalUserRealm() {
        return new SecurityRealm<NormalUser>(
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
                    throw new SecurityRealmAuthException(ErrorCodes.BAD_CREDENTIALS);
                }
                NormalUser user = optionalUser.get();


                // WARNING: FOR DEMO PURPOSE ONLY
                if(!user.getPassword().equals(password)){
                    throw new SecurityRealmAuthException(ErrorCodes.BAD_CREDENTIALS);
                }

                // TODO: send otp to mobile
                String otp = "1234"; // random
                user.setOtp(otp);
                user = normalUserRepo.save(user);

                return new SecurityRealmAuth<>(user, user.getUsername(), null, StepNames.OTP);
            })
            .addAuthStep(StepNames.OTP, (previousStepAuth, request) -> {
                String otp = request.getHeader(Headers.OTP);

                NormalUser user = previousStepAuth.getPrincipal();

                if(!user.getOtp().equals(otp)){
                    throw new SecurityRealmAuthException(ErrorCodes.BAD_OTP);
                }

                // clear otp
                user.setOtp(otp);
                user = normalUserRepo.save(user);

                return new SecurityRealmAuth<>(user, user.getUsername(), null);
            });
    }

    @Bean
    public SecurityRealm<AdminUser> configureAdminUserRealm() {
        return new SecurityRealm<AdminUser>(
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
                    throw new SecurityRealmAuthException(ErrorCodes.BAD_CREDENTIALS);
                }
                AdminUser user = optionalUser.get();


                // WARNING: FOR DEMO PURPOSE ONLY
                if(!user.getPassword().equals(password)){
                    throw new SecurityRealmAuthException(ErrorCodes.BAD_CREDENTIALS);
                }

                // TODO: send otp to mobile
                String otp = "1234"; // random
                user.setOtp(otp);
                user = adminUserRepo.save(user);

                return new SecurityRealmAuth<>(user, user.getUsername(), null, StepNames.OTP);
            })
            .addAuthStep(StepNames.OTP, (previousStepAuth, request) -> {
                String otp = request.getHeader(Headers.OTP);

                AdminUser user = previousStepAuth.getPrincipal();

                if(!user.getOtp().equals(otp)){
                    throw new SecurityRealmAuthException(ErrorCodes.BAD_OTP);
                }

                // clear otp
                user.setOtp(otp);
                user = adminUserRepo.save(user);

                return new SecurityRealmAuth<>(user, user.getUsername(), null);
            });
    }
}
