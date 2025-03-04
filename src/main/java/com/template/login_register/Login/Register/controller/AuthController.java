package com.template.login_register.Login.Register.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.template.login_register.Login.Register.dto.ApiResponseDto;
import com.template.login_register.Login.Register.dto.AuthResponse;
import com.template.login_register.Login.Register.dto.LoginRequest;
import com.template.login_register.Login.Register.dto.PasswordResetConfirmRequest;
import com.template.login_register.Login.Register.dto.PasswordResetRequest;
import com.template.login_register.Login.Register.dto.RegisterRequest;
import com.template.login_register.Login.Register.dto.VerifyOtpRequest;
import com.template.login_register.Login.Register.service.AuthService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "Register a new user", description = "Register a new user and send OTP verification email")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "User registered successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid input or email already exists")
    })
    @PostMapping("/register")
    public ResponseEntity<ApiResponseDto<Void>> register(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponseDto.success("Registration successful. Please check your email for verification OTP"));
    }

    @Operation(summary = "Verify email with OTP", description = "Verify user email using the OTP sent during registration")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Email verified successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid or expired OTP")
    })
    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponseDto<Boolean>> verifyOtp(@Valid @RequestBody VerifyOtpRequest request) {
        boolean verified = authService.verifyOtp(request);

        if (verified) {
            return ResponseEntity.ok(ApiResponseDto.success("Email verified successfully", true));
        } else {
            return ResponseEntity.badRequest()
                    .body(ApiResponseDto.error("Invalid or expired OTP"));
        }
    }

    @Operation(summary = "User login", description = "Authenticate user and return JWT token")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Login successful", 
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "401", description = "Invalid credentials"),
        @ApiResponse(responseCode = "400", description = "Email not verified")
    })
    @PostMapping("/login")
    public ResponseEntity<ApiResponseDto<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse authResponse = authService.login(request);
        return ResponseEntity.ok(ApiResponseDto.success("Login successful", authResponse));
    }

    @Operation(summary = "Resend OTP for email verification", description = "Resend OTP to the user's email for verification")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "OTP resent successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid email")
    })
    @PostMapping("/resend-otp")
    public ResponseEntity<ApiResponseDto<Void>> resendOtp(@RequestParam @NotBlank @Email String email) {
        authService.resendOtp(email);
        return ResponseEntity.ok(ApiResponseDto.success("OTP resent successfully. Please check your email"));
    }

    @Operation(summary = "Request password reset", description = "Send password reset instructions to the user's email")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password reset instructions sent"),
        @ApiResponse(responseCode = "400", description = "Invalid email")
    })
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponseDto<Void>> forgotPassword(@Valid @RequestBody PasswordResetRequest request) {
        authService.requestPasswordReset(request);
        return ResponseEntity.ok(ApiResponseDto.success("Password reset instructions sent to your email"));
    }

    @Operation(summary = "Reset password using OTP", description = "Reset user password using the OTP sent to their email")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password reset successful"),
        @ApiResponse(responseCode = "400", description = "Invalid or expired OTP")
    })
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponseDto<Boolean>> resetPassword(@Valid @RequestBody PasswordResetConfirmRequest request) {
        boolean resetSuccessful = authService.resetPassword(request);

        if (resetSuccessful) {
            return ResponseEntity.ok(ApiResponseDto.success("Password reset successful", true));
        } else {
            return ResponseEntity.badRequest()
                    .body(ApiResponseDto.error("Invalid or expired OTP"));
        }
    }

    @Operation(summary = "Register a new admin user", description = "Create a new user with admin privileges")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Admin user registered successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid input or email already exists"),
        @ApiResponse(responseCode = "403", description = "Access denied, requires admin privileges")
    })
    @PreAuthorize("hasRole('ROLE_ADMIN')") // Only admins can create other admins
    @PostMapping("/register-admin")
    public ResponseEntity<ApiResponseDto<Void>> registerAdmin(@Valid @RequestBody RegisterRequest request) {
        authService.registerAdmin(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponseDto.success("Admin user registered successfully"));
    }
}
