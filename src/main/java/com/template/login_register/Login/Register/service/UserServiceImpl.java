package com.template.login_register.Login.Register.service;

import com.template.login_register.Login.Register.entity.Role;
import com.template.login_register.Login.Register.entity.User;
import com.template.login_register.Login.Register.exception.ResourceNotFoundException;
import com.template.login_register.Login.Register.repository.RoleRepository;
import com.template.login_register.Login.Register.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final CachedUserService cachedUserService;

    @Override
    @Transactional
    public User createUser(String firstName, String lastName, String email, String password) {
        User user = User.builder()
                .firstName(firstName)
                .lastName(lastName)
                .email(email.toLowerCase())
                .password(passwordEncoder.encode(password))
                .emailVerified(false)
                .roles(new HashSet<>())
                .build();
        
        // Assign default ROLE_USER
        Role userRole = roleRepository.findByName(Role.ROLE_USER)
                .orElseThrow(() -> new ResourceNotFoundException("Default user role not found"));
        
        user.getRoles().add(userRole);
        
        log.info("Creating new user with email: {}", email);
        return cachedUserService.saveUser(user);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> getUserByEmail(String email) {
        return cachedUserService.getUserByEmail(email.toLowerCase());
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> getUserById(UUID id) {
        return userRepository.findById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email.toLowerCase());
    }

    @Override
    @Transactional
    public void verifyUserEmail(User user) {
        user.setEmailVerified(true);
        cachedUserService.saveUser(user);
        log.info("Email verified for user: {}", user.getEmail());
    }

    @Override
    @Transactional
    public User assignUserRole(User user, String roleName) {
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + roleName));
        
        user.getRoles().add(role);
        User savedUser = cachedUserService.saveUser(user);
        
        log.info("Role {} assigned to user: {}", roleName, user.getEmail());
        return savedUser;
    }
    
    @Override
    @Transactional
    public User saveUser(User user) {
        return cachedUserService.saveUser(user);
    }
}