package com.template.login_register.Login.Register.controller;

import com.template.login_register.Login.Register.dto.ApiResponseDto;
import com.template.login_register.Login.Register.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class LogoutController {

    private final JwtTokenProvider tokenProvider;
    
    @PostMapping("/logout")
    public ResponseEntity<ApiResponseDto<Void>> logout(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            String token = bearerToken.substring(7);
            tokenProvider.invalidateToken(token);
            return ResponseEntity.ok(ApiResponseDto.success("Logout successful"));
        }
        return ResponseEntity.badRequest().body(ApiResponseDto.error("No authentication token found"));
    }
}