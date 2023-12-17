package net.coder966.spring.multisecurityrealms.repo;

import java.util.Optional;
import net.coder966.spring.multisecurityrealms.entity.NormalUser;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NormalUserRepo extends CrudRepository<NormalUser, Long> {

    Optional<NormalUser> findByUsername(String username);
}
