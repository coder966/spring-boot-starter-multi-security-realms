package com.example.spring.multisecurityrealms.repo;

import com.example.spring.multisecurityrealms.entity.Badge;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BadgeRepo extends CrudRepository<Badge, Long> {

}
