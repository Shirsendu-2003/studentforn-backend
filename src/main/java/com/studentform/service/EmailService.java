package com.studentform.service;

import org.springframework.stereotype.Service;

@Service
public class EmailService {

    // Email temporarily disabled
    public void sendVerificationEmail(String toEmail, String name) {
        System.out.println("📧 Email sending disabled. Skipping email for: " + toEmail);
    }
}
