package com.template.login_register.Login.Register.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.template.login_register.Login.Register.entity.Role;
import com.template.login_register.Login.Register.entity.User;
import com.template.login_register.Login.Register.exception.ResourceNotFoundException;
import com.template.login_register.Login.Register.repository.RoleRepository;
import com.template.login_register.Login.Register.repository.UserRepository;

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

        // Find or create the default user role
        Role userRole = roleRepository.findByName(Role.ROLE_USER)
                .orElseGet(() -> {
                    log.warn("Default user role not found, creating it now");
                    Role newRole = Role.builder()
                            .name(Role.ROLE_USER)
                            .description("Regular user with basic privileges")
                            .build();
                    return roleRepository.save(newRole);
                });

        user.getRoles().add(userRole);

        log.info("Creating new user with email: {}", email);
        return userRepository.save(user);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email.toLowerCase());
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
        userRepository.save(user);
        log.info("Email verified for user: {}", user.getEmail());
    }

    @Override
    @Transactional
    public User assignUserRole(User user, String roleName) {
        Role role = roleRepository.findByName(roleName)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + roleName));

        user.getRoles().add(role);
        User savedUser = userRepository.save(user);

        log.info("Role {} assigned to user: {}", roleName, user.getEmail());
        return savedUser;
    }

    @Override
    @Transactional
    public User saveUser(User user) {
        log.info("Saving user: {}", user.getEmail());
        return userRepository.save(user);
    }
}
