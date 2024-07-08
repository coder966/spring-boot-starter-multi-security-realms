package com.example.repo;

import com.example.entity.Badge;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BadgeRepo extends CrudRepository<Badge, Long> {

}
