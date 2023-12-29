package net.coder966.spring.multisecurityrealms.repo;

import net.coder966.spring.multisecurityrealms.entity.Badge;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BadgeRepo extends CrudRepository<Badge, Long> {

}
