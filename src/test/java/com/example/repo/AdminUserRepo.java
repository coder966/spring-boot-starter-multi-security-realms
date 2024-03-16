package com.example.spring.multisecurityrealms.repo;

import com.example.spring.multisecurityrealms.entity.AdminUser;
import java.util.Optional;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AdminUserRepo extends CrudRepository<AdminUser, Long> {

    Optional<AdminUser> findByUsername(String username);
}
