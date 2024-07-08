package com.example.repo;

import com.example.entity.NormalUser;
import java.util.Optional;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NormalUserRepo extends CrudRepository<NormalUser, Long> {

    Optional<NormalUser> findByUsername(String username);
}
