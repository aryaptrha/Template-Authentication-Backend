package com.template.login_register.Login.Register.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.template.login_register.Login.Register.dto.ApiResponse;
import com.template.login_register.Login.Register.dto.AuthResponse;
import com.template.login_register.Login.Register.dto.LoginRequest;
import com.template.login_register.Login.Register.dto.PasswordResetConfirmRequest;
import com.template.login_register.Login.Register.dto.PasswordResetRequest;
import com.template.login_register.Login.Register.dto.RegisterRequest;
import com.template.login_register.Login.Register.dto.VerifyOtpRequest;
import com.template.login_register.Login.Register.service.AuthService;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Void>> register(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Registration successful. Please check your email for verification OTP"));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse<Boolean>> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        boolean verified = authService.verifyOtp(request);

        if (verified) {
            return ResponseEntity.ok(ApiResponse.success("Email verified successfully", true));
        } else {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Invalid or expired OTP"));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse authResponse = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success("Login successful", authResponse));
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<ApiResponse<Void>> resendOtp(@RequestParam @NotBlank @Email String email) {
        authService.resendOtp(email);
        return ResponseEntity.ok(ApiResponse.success("OTP resent successfully. Please check your email"));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@Valid @RequestBody PasswordResetRequest request) {
        authService.requestPasswordReset(request);
        return ResponseEntity.ok(ApiResponse.success("Password reset instructions sent to your email"));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Boolean>> resetPassword(@Valid @RequestBody PasswordResetConfirmRequest request) {
        boolean resetSuccessful = authService.resetPassword(request);

        if (resetSuccessful) {
            return ResponseEntity.ok(ApiResponse.success("Password reset successful", true));
        } else {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.error("Invalid or expired OTP"));
        }
    }

    @PostMapping("/register-admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')") // Only admins can create other admins
    public ResponseEntity<ApiResponse<Void>> registerAdmin(@Valid @RequestBody RegisterRequest request) {
        authService.registerAdmin(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Admin user registered successfully"));
    }
}
