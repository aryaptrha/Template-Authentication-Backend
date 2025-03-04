package com.template.login_register.Login.Register.service;

import java.util.Optional;
import java.util.UUID;

import com.template.login_register.Login.Register.entity.User;

public interface UserService {

    User createUser(String firstName, String lastName, String email, String password);
    
    Optional<User> getUserByEmail(String email);
    
    Optional<User> getUserById(UUID id);
    
    boolean existsByEmail(String email);
    
    void verifyUserEmail(User user);
    
    User assignUserRole(User user, String roleName);
    
    User saveUser(User user);
    
}