package com.template.login_register.Login.Register.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;

    @Async
    @Override
    public void sendVerificationEmail(String to, String name, String otp) throws MessagingException {
        log.info("Sending verification email to: {}", to);
        
        Map<String, Object> variables = new HashMap<>();
        variables.put("name", name);
        variables.put("otp", otp);
        
        String emailContent = processTemplate("verification-email", variables);
        
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        
        helper.setTo(to);
        helper.setSubject("Email Verification");
        helper.setText(emailContent, true);
        
        mailSender.send(message);
        log.info("Verification email sent to: {}", to);
    }

    @Async
    @Override
    public void sendPasswordResetEmail(String to, String name, String otp) throws MessagingException {
        log.info("Sending password reset email to: {}", to);
        
        Map<String, Object> variables = new HashMap<>();
        variables.put("name", name);
        variables.put("otp", otp);
        variables.put("resetLink", "http://localhost:3000/reset-password");
        
        String emailContent = processTemplate("password-reset-email", variables);
        
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        
        helper.setTo(to);
        helper.setSubject("Password Reset Request");
        helper.setText(emailContent, true);
        
        mailSender.send(message);
        log.info("Password reset email sent to: {}", to);
    }
    
    private String processTemplate(String templateName, Map<String, Object> variables) {
        Context context = new Context();
        context.setVariables(variables);
        return templateEngine.process(templateName, context);
    }
}
