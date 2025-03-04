package com.template.login_register.Login.Register.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.template.login_register.Login.Register.entity.User;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    
    Optional<User> findByEmail(String email);
    
    boolean existsByEmail(String email);
}