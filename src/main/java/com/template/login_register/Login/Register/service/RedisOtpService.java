package com.template.login_register.Login.Register.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RedisOtpService {

    private final RedisTemplate<String, Object> redisTemplate;
    
    // OTP prefix for Redis keys
    private static final String OTP_PREFIX = "otp:";
    
    /**
     * Save OTP to Redis
     * @param email User email
     * @param otp The OTP code
     * @param type OTP type (registration, password reset)
     * @param expiryTimeInMinutes Expiry time in minutes
     */
    public void saveOtp(String email, String otp, String type, int expiryTimeInMinutes) {
        String key = generateOtpKey(email, type);
        redisTemplate.opsForValue().set(key, otp, expiryTimeInMinutes, TimeUnit.MINUTES);
        log.info("OTP saved to Redis for email: {}, type: {}", email, type);
    }
    
    /**
     * Verify OTP from Redis
     * @param email User email
     * @param otp The OTP code to verify
     * @param type OTP type (registration, password reset)
     * @return true if OTP is valid
     */
    public boolean verifyOtp(String email, String otp, String type) {
        String key = generateOtpKey(email, type);
        Object storedOtp = redisTemplate.opsForValue().get(key);
        
        if (storedOtp == null) {
            log.warn("No OTP found in Redis for email: {}, type: {}", email, type);
            return false;
        }
        
        boolean isValid = storedOtp.toString().equals(otp);
        
        if (isValid) {
            // Delete OTP after successful verification
            redisTemplate.delete(key);
            log.info("OTP verified and deleted for email: {}, type: {}", email, type);
        } else {
            log.warn("Invalid OTP attempt for email: {}, type: {}", email, type);
        }
        
        return isValid;
    }
    
    /**
     * Delete existing OTP for a user
     * @param email User email
     * @param type OTP type
     */
    public void deleteOtp(String email, String type) {
        String key = generateOtpKey(email, type);
        redisTemplate.delete(key);
        log.info("OTP deleted for email: {}, type: {}", email, type);
    }
    
    private String generateOtpKey(String email, String type) {
        return OTP_PREFIX + type + ":" + email;
    }
}