package com.template.login_register.Login.Register.service;

import com.template.login_register.Login.Register.entity.Otp;
import com.template.login_register.Login.Register.util.OtpUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class OtpServiceImpl implements OtpService {

    private final RedisOtpService redisOtpService;
    private final OtpUtil otpUtil;
    
    @Value("${app.otp.validity-minutes}")
    private int otpValidityMinutes;

    @Override
    @Transactional
    public Otp generateOtp(String email, Otp.OtpType type) {
        // Delete any existing OTPs for this email and type
        redisOtpService.deleteOtp(email, type.toString());
        
        // Generate a new OTP
        String otpCode = otpUtil.generateOtp();
        
        // Store in Redis
        redisOtpService.saveOtp(email, otpCode, type.toString(), otpValidityMinutes);
        
        // Create OTP object to return (we're not saving to DB anymore)
        return Otp.builder()
                .email(email)
                .code(otpCode)
                .type(type)
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public boolean verifyOtp(String email, String otpCode, Otp.OtpType type) {
        return redisOtpService.verifyOtp(email, otpCode, type.toString());
    }

    @Override
    @Transactional
    public void markOtpAsUsed(Otp otp) {
        // With Redis implementation, verification automatically invalidates the OTP
        // so nothing needed here
        log.info("OTP marked as used for email: {}", otp.getEmail());
    }

    @Override
    @Transactional
    public void deleteExistingOtps(String email, Otp.OtpType type) {
        redisOtpService.deleteOtp(email, type.toString());
        log.info("Deleted existing OTPs for email: {} and type: {}", email, type);
    }
    
    @Override
    @Transactional(readOnly = true)
    public Optional<Otp> getOtpByEmailAndCode(String email, String otpCode, Otp.OtpType type) {
        // Check if OTP exists in Redis
        boolean exists = redisOtpService.verifyOtp(email, otpCode, type.toString());
        
        if (exists) {
            // If it exists, create an Otp object (but don't verify it yet)
            Otp otp = Otp.builder()
                    .email(email)
                    .code(otpCode)
                    .type(type)
                    .used(false)
                    .build();
            return Optional.of(otp);
        }
        
        return Optional.empty();
    }
}