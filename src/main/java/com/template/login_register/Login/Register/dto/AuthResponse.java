package com.template.login_register.Login.Register.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private String token;
    private String tokenType;
    private String email;
    private String fullName;
    private List<String> roles;
    private boolean emailVerified;
    private LocalDateTime lastLoginAt;
}