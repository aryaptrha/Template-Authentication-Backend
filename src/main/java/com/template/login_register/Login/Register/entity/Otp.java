package com.template.login_register.Login.Register.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "otps")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Otp {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String code;

    @Column(nullable = false)
    private LocalDateTime expiryTime;

    @Column(nullable = false)
    private boolean used;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OtpType type;
    
    public enum OtpType {
        REGISTRATION,
        PASSWORD_RESET
    }
    
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryTime);
    }
}
