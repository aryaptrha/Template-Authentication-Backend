package com.template.login_register.Login.Register.service;

import java.util.Optional;

import com.template.login_register.Login.Register.entity.Otp;

public interface OtpService {

    Otp generateOtp(String email, Otp.OtpType type);
    
    boolean verifyOtp(String email, String otpCode, Otp.OtpType type);
    
    void markOtpAsUsed(Otp otp);
    
    void deleteExistingOtps(String email, Otp.OtpType type);
    
    Optional<Otp> getOtpByEmailAndCode(String email, String otpCode, Otp.OtpType type);
}