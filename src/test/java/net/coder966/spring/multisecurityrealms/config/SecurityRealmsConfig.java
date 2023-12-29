package net.coder966.spring.multisecurityrealms.config;

import java.util.Optional;
import lombok.AllArgsConstructor;
import net.coder966.spring.multisecurityrealms.entity.AdminUser;
import net.coder966.spring.multisecurityrealms.entity.NormalUser;
import net.coder966.spring.multisecurityrealms.exception.SecurityRealmAuthenticationException;
import net.coder966.spring.multisecurityrealms.model.SecurityRealm;
import net.coder966.spring.multisecurityrealms.model.SecurityRealmAuthentication;
import net.coder966.spring.multisecurityrealms.other.Constants.ErrorCodes;
import net.coder966.spring.multisecurityrealms.other.Constants.Headers;
import net.coder966.spring.multisecurityrealms.other.Constants.StepNames;
import net.coder966.spring.multisecurityrealms.repo.AdminUserRepo;
import net.coder966.spring.multisecurityrealms.repo.NormalUserRepo;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

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
            .publicApi(AntPathRequestMatcher.antMatcher("/normal-user/my-first-open-api"))
            .publicApi(AntPathRequestMatcher.antMatcher("/normal-user/my-second-open-api"))
            .setFirstAuthStep(request -> {
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

                return new SecurityRealmAuthentication<>(user, user.getUsername(), null, StepNames.OTP);
            })
            .addAuthStep(StepNames.OTP, (previousStepAuth, request) -> {
                String otp = request.getHeader(Headers.OTP);

                NormalUser user = previousStepAuth.getPrincipal();

                if(!user.getOtp().equals(otp)){
                    throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_OTP);
                }

                // clear otp
                user.setOtp(otp);
                user = normalUserRepo.save(user);

                return new SecurityRealmAuthentication<>(user, user.getUsername(), null);
            });
    }

    @Bean
    public SecurityRealm<AdminUser> configureAdminUserRealm() {
        return new SecurityRealm<AdminUser>(
                "ADMIN_USER",
                "/admin-user/login",
                "/admin-user/logout"
            )
            .publicApi(AntPathRequestMatcher.antMatcher("/admin-user/my-first-open-api"))
            .publicApi(AntPathRequestMatcher.antMatcher("/admin-user/my-second-open-api"))
            .setFirstAuthStep(request -> {
                // WARNING: FOR DEMO PURPOSE ONLY

                String username = request.getHeader(Headers.USERNAME);
                String password = request.getHeader(Headers.PASSWORD);

                Optional<AdminUser> optionalUser = adminUserRepo.findByUsername(username);
                if(optionalUser.isEmpty()){
                    throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
                }
                AdminUser user = optionalUser.get();


                // WARNING: FOR DEMO PURPOSE ONLY
                if(!user.getPassword().equals(password)){
                    throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_CREDENTIALS);
                }

                // TODO: send otp to mobile
                String otp = "1234"; // random
                user.setOtp(otp);
                user = adminUserRepo.save(user);

                return new SecurityRealmAuthentication<>(user, user.getUsername(), null, StepNames.OTP);
            })
            .addAuthStep(StepNames.OTP, (previousStepAuth, request) -> {
                String otp = request.getHeader(Headers.OTP);

                AdminUser user = previousStepAuth.getPrincipal();

                if(!user.getOtp().equals(otp)){
                    throw new SecurityRealmAuthenticationException(ErrorCodes.BAD_OTP);
                }

                // clear otp
                user.setOtp(otp);
                user = adminUserRepo.save(user);

                return new SecurityRealmAuthentication<>(user, user.getUsername(), null);
            });
    }
}