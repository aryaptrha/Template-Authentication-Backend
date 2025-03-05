package com.template.login_register.Login.Register.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RedisTokenService {

    private final RedisTemplate<String, Object> redisTemplate;
    
    // Token prefix for Redis keys
    private static final String TOKEN_PREFIX = "token:";
    private static final String BLACKLIST_PREFIX = "blacklist:token:";
    
    /**
     * Store token details in Redis
     * @param userId User ID
     * @param token JWT token
     * @param expiryTimeInMillis Token expiry time in milliseconds
     */
    public void saveToken(String userId, String token, long expiryTimeInMillis) {
        String key = TOKEN_PREFIX + userId;
        redisTemplate.opsForValue().set(key, token, expiryTimeInMillis, TimeUnit.MILLISECONDS);
        log.info("Token saved to Redis for user ID: {}", userId);
    }
    
    /**
     * Validate if token exists and is valid
     * @param userId User ID
     * @param token JWT token
     * @return true if token is valid
     */
    public boolean validateToken(String userId, String token) {
        String key = TOKEN_PREFIX + userId;
        Object storedToken = redisTemplate.opsForValue().get(key);
        
        if (storedToken == null) {
            log.warn("No token found in Redis for user ID: {}", userId);
            return false;
        }
        
        return storedToken.toString().equals(token) && !isTokenBlacklisted(token);
    }
    
    /**
     * Invalidate token (on logout)
     * @param userId User ID
     * @param token JWT token
     * @param expiryTimeInMillis How long to keep in blacklist
     */
    public void invalidateToken(String userId, String token, long expiryTimeInMillis) {
        // Delete the token from user's active tokens
        String userKey = TOKEN_PREFIX + userId;
        redisTemplate.delete(userKey);
        
        // Add to blacklist
        String blacklistKey = BLACKLIST_PREFIX + token;
        redisTemplate.opsForValue().set(blacklistKey, "BLACKLISTED", expiryTimeInMillis, TimeUnit.MILLISECONDS);
        
        log.info("Token invalidated for user ID: {}", userId);
    }
    
    /**
     * Check if token is blacklisted
     * @param token JWT token
     * @return true if token is blacklisted
     */
    public boolean isTokenBlacklisted(String token) {
        String blacklistKey = BLACKLIST_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey));
    }
}