package net.coder966.spring.multisecurityrealms.config;

import java.util.List;
import lombok.AllArgsConstructor;
import net.coder966.spring.multisecurityrealms.entity.AdminUser;
import net.coder966.spring.multisecurityrealms.entity.NormalUser;
import net.coder966.spring.multisecurityrealms.repo.AdminUserRepo;
import net.coder966.spring.multisecurityrealms.repo.NormalUserRepo;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Configuration;

@AllArgsConstructor
@Configuration
public class InitializeDatabaseWithData implements ApplicationRunner {

    private final NormalUserRepo normalUserRepo;
    private final AdminUserRepo adminUserRepo;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        normalUserRepo.saveAll(List.of(
            new NormalUser("Mohammed", "mohammed", "mpass"),
            new NormalUser("Ali", "ali", "apass")
        ));

        adminUserRepo.saveAll(List.of(
            new AdminUser("Khalid", "khalid", "kpass"),
            new AdminUser("Hassan", "hassan", "hpass")
        ));
    }
}
