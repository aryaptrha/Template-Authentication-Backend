package com.template.login_register.Login.Register.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Component
public class OtpUtil {

    @Value("${app.otp.validity-minutes}")
    private int otpValidityMinutes;
    
    @Value("${app.otp.length}")
    private int otpLength;

    private static final String OTP_CHARS = "0123456789";
    private final SecureRandom random = new SecureRandom();

    public String generateOtp() {
        StringBuilder otp = new StringBuilder(otpLength);
        for (int i = 0; i < otpLength; i++) {
            otp.append(OTP_CHARS.charAt(random.nextInt(OTP_CHARS.length())));
        }
        return otp.toString();
    }

    public LocalDateTime calculateExpiryTime() {
        return LocalDateTime.now().plusMinutes(otpValidityMinutes);
    }
}