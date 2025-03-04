package com.template.login_register.Login.Register.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.template.login_register.Login.Register.entity.Otp;
import com.template.login_register.Login.Register.repository.OtpRepository;
import com.template.login_register.Login.Register.util.OtpUtil;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class OtpServiceImpl implements OtpService {

    private final OtpRepository otpRepository;
    private final OtpUtil otpUtil;

    @Override
    @Transactional
    public Otp generateOtp(String email, Otp.OtpType type) {
        // Delete any existing OTPs for this email and type
        deleteExistingOtps(email, type);
        
        // Generate a new OTP
        String otpCode = otpUtil.generateOtp();
        
        // Create and save the OTP entity
        Otp otp = Otp.builder()
                .email(email)
                .code(otpCode)
                .type(type)
                .expiryTime(otpUtil.calculateExpiryTime())
                .used(false)
                .build();
        
        return otpRepository.save(otp);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean verifyOtp(String email, String otpCode, Otp.OtpType type) {
        Optional<Otp> otpOptional = otpRepository.findByEmailAndCodeAndTypeAndUsedFalse(email, otpCode, type);
        
        if (otpOptional.isEmpty()) {
            log.warn("No valid OTP found for email: {} and type: {}", email, type);
            return false;
        }
        
        Otp otp = otpOptional.get();
        
        if (otp.isExpired()) {
            log.warn("OTP has expired for email: {}", email);
            return false;
        }
        
        return true;
    }

    @Override
    @Transactional
    public void markOtpAsUsed(Otp otp) {
        otp.setUsed(true);
        otpRepository.save(otp);
        log.info("OTP marked as used for email: {}", otp.getEmail());
    }

    @Override
    @Transactional
    public void deleteExistingOtps(String email, Otp.OtpType type) {
        otpRepository.deleteByEmailAndType(email, type);
        log.info("Deleted existing OTPs for email: {} and type: {}", email, type);
    }
    
    @Override
    @Transactional(readOnly = true)
    public Optional<Otp> getOtpByEmailAndCode(String email, String otpCode, Otp.OtpType type) {
        return otpRepository.findByEmailAndCodeAndTypeAndUsedFalse(email, otpCode, type);
    }
}