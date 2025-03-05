package com.template.login_register.Login.Register.service;

import com.template.login_register.Login.Register.entity.User;
import com.template.login_register.Login.Register.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class CachedUserService {

    private final UserRepository userRepository;
    private final RedisTemplate<String, String> redisTemplate;
    
    private static final String USER_CACHE_PREFIX = "user:";
    private static final long USER_CACHE_TTL = 3600; // seconds
    
    public Optional<User> getUserByEmail(String email) {
        String cacheKey = USER_CACHE_PREFIX + email;
        String userIdStr = redisTemplate.opsForValue().get(cacheKey);
        
        if (userIdStr != null) {
            try {
                UUID userId = UUID.fromString(userIdStr);
                return userRepository.findById(userId);
            } catch (IllegalArgumentException e) {
                log.error("Invalid UUID in cache for user email: {}", email, e);
            }
        }
        
        Optional<User> userOpt = userRepository.findByEmail(email.toLowerCase());
        userOpt.ifPresent(user -> {
            redisTemplate.opsForValue().set(
                cacheKey, 
                user.getId().toString(),
                USER_CACHE_TTL, 
                TimeUnit.SECONDS
            );
        });
        
        return userOpt;
    }
    
    public void invalidateUserCache(String email) {
        redisTemplate.delete(USER_CACHE_PREFIX + email);
    }
    
    @CacheEvict(value = "users", key = "#user.email")
    @Transactional
    public User saveUser(User user) {
        log.debug("Saving user and evicting cache: {}", user.getEmail());
        return userRepository.save(user);
    }
    
    @CacheEvict(value = "users", key = "#email")
    public void evictUserCache(String email) {
        log.debug("Evicting user cache: {}", email);
    }
}