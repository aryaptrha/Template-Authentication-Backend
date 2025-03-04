package com.template.login_register.Login.Register.service;

import com.template.login_register.Login.Register.dto.AuthResponse;
import com.template.login_register.Login.Register.dto.LoginRequest;
import com.template.login_register.Login.Register.dto.PasswordResetConfirmRequest;
import com.template.login_register.Login.Register.dto.PasswordResetRequest;
import com.template.login_register.Login.Register.dto.RegisterRequest;
import com.template.login_register.Login.Register.dto.VerifyOtpRequest;

public interface AuthService {

    void register(RegisterRequest request);
    
    boolean verifyOtp(VerifyOtpRequest request);
    
    AuthResponse login(LoginRequest request);
    
    void resendOtp(String email);

    void requestPasswordReset(PasswordResetRequest request);
    
    boolean resetPassword(PasswordResetConfirmRequest request);

    void registerAdmin(RegisterRequest request);
}
