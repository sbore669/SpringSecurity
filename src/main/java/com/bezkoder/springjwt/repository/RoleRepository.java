package com.bezkoder.springjwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.bezkoder.springjwt.models.ERole;
import com.bezkoder.springjwt.models.Role;

import javax.transaction.Transactional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);

  Role findByName(String name);

  @Modifying
  @Transactional
  @Query(value = "INSERT INTO roles (name) VALUES ('ROLE_ADMIN'),('ROLE_USER'),('MODERATOR');",nativeQuery = true)
  void creationRole();
}
