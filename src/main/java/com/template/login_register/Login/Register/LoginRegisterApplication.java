package com.template.login_register.Login.Register;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class LoginRegisterApplication {

    public static void main(String[] args) {
        SpringApplication.run(LoginRegisterApplication.class, args);
    }
}