package com.template.login_register.Login.Register.service;

import jakarta.mail.MessagingException;

public interface EmailService {

    void sendVerificationEmail(String to, String name, String otp) throws MessagingException;
    
    void sendPasswordResetEmail(String to, String name, String otp) throws MessagingException;
}