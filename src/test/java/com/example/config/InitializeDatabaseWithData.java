package com.example.config;

import com.example.entity.AdminUser;
import com.example.entity.Badge;
import com.example.entity.NormalUser;
import com.example.repo.AdminUserRepo;
import com.example.repo.BadgeRepo;
import com.example.repo.NormalUserRepo;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import lombok.AllArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Configuration;

@AllArgsConstructor
@Configuration
public class InitializeDatabaseWithData implements ApplicationRunner {

    private final BadgeRepo badgeRepo;
    private final NormalUserRepo normalUserRepo;
    private final AdminUserRepo adminUserRepo;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Iterable<Badge> badgesIterable = badgeRepo.saveAll(List.of(
            new Badge("test1"),
            new Badge("test2"),
            new Badge("test3")
        ));

        Set<Badge> badges = new HashSet<>();
        badgesIterable.iterator().forEachRemaining(badges::add);

        normalUserRepo.saveAll(List.of(
            new NormalUser("Mohammed", "mohammed", "mpass"),
            new NormalUser("Ali", "ali", "apass")
        ));

        adminUserRepo.saveAll(List.of(
            new AdminUser("Khalid", "khalid", "kpass", badges),
            new AdminUser("Hassan", "hassan", "hpass", badges)
        ));
    }
}
