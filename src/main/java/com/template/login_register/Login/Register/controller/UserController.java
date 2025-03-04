package com.template.login_register.Login.Register.controller;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import com.template.login_register.Login.Register.dto.ApiResponse;
import com.template.login_register.Login.Register.dto.RegisterRequest;
import com.template.login_register.Login.Register.entity.Role;
import com.template.login_register.Login.Register.entity.User;
import com.template.login_register.Login.Register.exception.ResourceNotFoundException;
import com.template.login_register.Login.Register.security.UserDetailsImpl;
import com.template.login_register.Login.Register.service.AuthService;
import com.template.login_register.Login.Register.service.UserService;

import jakarta.validation.Valid;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

        private final UserService userService;
        private final AuthService authService;

        @GetMapping("/me")
        public ResponseEntity<ApiResponse<Map<String, Object>>> getCurrentUser() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                // Get the username (email) from the authentication
                String email = authentication.getName();

                // Fetch the complete user from the database
                User user = userService.getUserByEmail(email)
                                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

                Map<String, Object> userData = new HashMap<>();
                userData.put("id", user.getId());
                userData.put("email", user.getEmail());
                userData.put("firstName", user.getFirstName());
                userData.put("lastName", user.getLastName());
                userData.put("emailVerified", user.isEmailVerified());
                userData.put("lastLoginAt", user.getLastLoginAt());
                userData.put("roles", user.getRoles().stream()
                                .map(Role::getName)
                                .collect(Collectors.toList()));

                return ResponseEntity.ok(ApiResponse.success("Current user data", userData));
        }

        @PutMapping("/{userId}/roles/{roleName}")
        @PreAuthorize("hasRole('ROLE_ADMIN')")
        public ResponseEntity<ApiResponse<User>> assignRole(
                        @PathVariable UUID userId,
                        @PathVariable String roleName) {

                User user = userService.getUserById(userId)
                                .orElseThrow(() -> new IllegalArgumentException("User not found"));

                User updatedUser = userService.assignUserRole(user, roleName);

                return ResponseEntity.ok(ApiResponse.success("Role assigned successfully", updatedUser));
        }
}
