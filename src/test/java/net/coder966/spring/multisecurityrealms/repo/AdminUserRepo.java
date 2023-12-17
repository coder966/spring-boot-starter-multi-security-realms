package net.coder966.spring.multisecurityrealms.repo;

import java.util.Optional;
import net.coder966.spring.multisecurityrealms.entity.AdminUser;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AdminUserRepo extends CrudRepository<AdminUser, Long> {

    Optional<AdminUser> findByUsername(String username);
}
