package com.template.login_register.Login.Register.controller;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import com.template.login_register.Login.Register.dto.ApiResponseDto;
import com.template.login_register.Login.Register.entity.Role;
import com.template.login_register.Login.Register.entity.User;
import com.template.login_register.Login.Register.exception.ResourceNotFoundException;
import com.template.login_register.Login.Register.service.UserService;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

        private final UserService userService;

        @Operation(summary = "Get current user details", description = "Fetches the details of the currently authenticated user")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "User details fetched successfully",
                                        content = @Content(mediaType = "application/json",
                                                        schema = @Schema(implementation = ApiResponseDto.class))),
                        @ApiResponse(responseCode = "401", description = "Unauthorized",
                                        content = @Content(mediaType = "application/json",
                                                        schema = @Schema(implementation = ApiResponseDto.class))),
                        @ApiResponse(responseCode = "404", description = "User not found",
                                        content = @Content(mediaType = "application/json",
                                                        schema = @Schema(implementation = ApiResponseDto.class)))
        })
        @GetMapping("/me")
        public ResponseEntity<ApiResponseDto<Map<String, Object>>> getCurrentUser() {
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

                return ResponseEntity.ok(ApiResponseDto.success("Current user data", userData));
        }

        @PutMapping("/{userId}/roles/{roleName}")
        @PreAuthorize("hasRole('ROLE_ADMIN')")
        public ResponseEntity<ApiResponseDto<User>> assignRole(
                        @PathVariable UUID userId,
                        @PathVariable String roleName) {

                User user = userService.getUserById(userId)
                                .orElseThrow(() -> new IllegalArgumentException("User not found"));

                User updatedUser = userService.assignUserRole(user, roleName);

                return ResponseEntity.ok(ApiResponseDto.success("Role assigned successfully", updatedUser));
        }
}
