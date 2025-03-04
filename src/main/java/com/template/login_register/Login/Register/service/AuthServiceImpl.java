package com.template.login_register.Login.Register.service;

import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.template.login_register.Login.Register.dto.AuthResponse;
import com.template.login_register.Login.Register.dto.LoginRequest;
import com.template.login_register.Login.Register.dto.PasswordResetConfirmRequest;
import com.template.login_register.Login.Register.dto.PasswordResetRequest;
import com.template.login_register.Login.Register.dto.RegisterRequest;
import com.template.login_register.Login.Register.dto.VerifyOtpRequest;
import com.template.login_register.Login.Register.entity.Otp;
import com.template.login_register.Login.Register.entity.Role;
import com.template.login_register.Login.Register.entity.User;
import com.template.login_register.Login.Register.exception.BadRequestException;
import com.template.login_register.Login.Register.exception.ResourceNotFoundException;
import com.template.login_register.Login.Register.security.JwtTokenProvider;
import com.template.login_register.Login.Register.security.UserDetailsImpl;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserService userService;
    private final OtpService otpService;
    private final EmailService emailService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void register(RegisterRequest request) {
        String email = request.getEmail().toLowerCase();

        if (userService.existsByEmail(email)) {
            throw new BadRequestException("Email is already registered");
        }

        // Create user
        User user = userService.createUser(
                request.getFirstName(),
                request.getLastName(),
                email,
                request.getPassword());

        // Generate and send OTP
        Otp otp = otpService.generateOtp(email, Otp.OtpType.REGISTRATION);

        try {
            emailService.sendVerificationEmail(
                    email,
                    user.getFirstName(),
                    otp.getCode());
        } catch (MessagingException e) {
            log.error("Failed to send verification email to {}: {}", email, e.getMessage());
            throw new BadRequestException("Failed to send verification email");
        }

        log.info("User registered successfully: {}", email);
    }

    @Override
    @Transactional
    public boolean verifyOtp(VerifyOtpRequest request) {
        String email = request.getEmail().toLowerCase();
        String otpCode = request.getOtp();

        // Check if the OTP is valid
        boolean isValid = otpService.verifyOtp(email, otpCode, Otp.OtpType.REGISTRATION);

        if (!isValid) {
            log.warn("Invalid or expired OTP for email: {}", email);
            return false;
        }

        // Find the user
        User user = userService.getUserByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Mark the user as verified
        userService.verifyUserEmail(user);

        // Mark the OTP as used
        Optional<Otp> otpOptional = otpService.getOtpByEmailAndCode(email, otpCode, Otp.OtpType.REGISTRATION);
        otpOptional.ifPresent(otpService::markOtpAsUsed);

        log.info("Email verified successfully for: {}", email);
        return true;
    }

    @Override
    @Transactional
    public AuthResponse login(LoginRequest request) {
        String email = request.getEmail().toLowerCase();

        // Check if the user exists
        User user = userService.getUserByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Check if the user's email is verified
        if (!user.isEmailVerified()) {
            throw new BadRequestException("Email not verified. Please verify your email first");
        }

        // Authenticate user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, request.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Update last login timestamp
        user.setLastLoginAt(LocalDateTime.now());
        userService.saveUser(user);

        // Generate JWT token
        String jwt = tokenProvider.generateToken(authentication);

        // Get user details
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        log.info("User logged in successfully: {}", email);

        return AuthResponse.builder()
                .token(jwt)
                .tokenType("Bearer")
                .email(userDetails.getEmail())
                .fullName(userDetails.getFirstName() + " " + userDetails.getLastName())
                .roles(roles)
                .emailVerified(userDetails.isEmailVerified())
                .lastLoginAt(user.getLastLoginAt())
                .build();
    }

    @Override
    @Transactional
    public void resendOtp(String email) {
        email = email.toLowerCase();

        // Check if the user exists
        User user = userService.getUserByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Check if the user's email is already verified
        if (user.isEmailVerified()) {
            throw new BadRequestException("Email is already verified");
        }

        // Generate new OTP and delete old ones
        Otp otp = otpService.generateOtp(email, Otp.OtpType.REGISTRATION);

        try {
            emailService.sendVerificationEmail(
                    email,
                    user.getFirstName(),
                    otp.getCode());
        } catch (MessagingException e) {
            log.error("Failed to resend verification email to {}: {}", email, e.getMessage());
            throw new BadRequestException("Failed to resend verification email");
        }

        log.info("OTP resent successfully for: {}", email);
    }

    @Override
    @Transactional
    public void requestPasswordReset(PasswordResetRequest request) {
        String email = request.getEmail().toLowerCase();

        // Check if the user exists
        User user = userService.getUserByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Generate password reset OTP
        Otp otp = otpService.generateOtp(email, Otp.OtpType.PASSWORD_RESET);

        try {
            emailService.sendPasswordResetEmail(
                    email,
                    user.getFirstName(),
                    otp.getCode());
        } catch (MessagingException e) {
            log.error("Failed to send password reset email to {}: {}", email, e.getMessage());
            throw new BadRequestException("Failed to send password reset email");
        }

        log.info("Password reset OTP sent to: {}", email);
    }

    @Override
    @Transactional
    public boolean resetPassword(PasswordResetConfirmRequest request) {
        String email = request.getEmail().toLowerCase();
        String otpCode = request.getOtp();

        // Check if the OTP is valid
        boolean isValid = otpService.verifyOtp(email, otpCode, Otp.OtpType.PASSWORD_RESET);

        if (!isValid) {
            log.warn("Invalid or expired OTP for password reset: {}", email);
            return false;
        }

        // Find the user
        User user = userService.getUserByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userService.saveUser(user);

        // Mark the OTP as used
        Optional<Otp> otpOptional = otpService.getOtpByEmailAndCode(email, otpCode, Otp.OtpType.PASSWORD_RESET);
        otpOptional.ifPresent(otpService::markOtpAsUsed);

        log.info("Password reset successful for: {}", email);
        return true;
    }

    @Override
    @Transactional
    public void registerAdmin(RegisterRequest request) {
        String email = request.getEmail().toLowerCase();

        if (userService.existsByEmail(email)) {
            throw new BadRequestException("Email is already registered");
        }

        // Create user
        User user = userService.createUser(
                request.getFirstName(),
                request.getLastName(),
                email,
                request.getPassword());

        // Skip OTP verification for admin users by setting emailVerified to true
        user.setEmailVerified(true);

        // Assign admin role
        userService.assignUserRole(user, Role.ROLE_ADMIN);

        // Save the updated user
        userService.saveUser(user);

        log.info("Admin user registered successfully: {}", email);
    }
}