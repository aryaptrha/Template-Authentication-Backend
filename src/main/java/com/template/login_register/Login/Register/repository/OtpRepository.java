package com.template.login_register.Login.Register.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.template.login_register.Login.Register.entity.Otp;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface OtpRepository extends JpaRepository<Otp, UUID> {
    
    Optional<Otp> findByEmailAndCodeAndTypeAndUsedFalse(String email, String code, Otp.OtpType type);
    
    void deleteByEmailAndType(String email, Otp.OtpType type);
}