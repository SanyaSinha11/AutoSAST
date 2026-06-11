package com.example.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;

/**
 * Logging Service - Contains log injection vulnerabilities and secure patterns.
 */
public class LoggingService {

    private static final Logger logger = LoggerFactory.getLogger(LoggingService.class);

    // ============================================================
    // TRUE POSITIVE: Log Injection via unsanitized input
    // Severity: MEDIUM
    // ============================================================
    public void logUserActionVulnerable(HttpServletRequest request) {
        String username = request.getParameter("username");
        String action = request.getParameter("action");
        
        // VULNERABLE: Direct logging of user input allows log forging
        // Attacker can inject: "admin\n2024-01-01 12:00:00 INFO Fake log entry"
        logger.info("User {} performed action: {}", username, action);
    }

    // ============================================================
    // FALSE POSITIVE: Log with sanitization
    // This should NOT be flagged
    // ============================================================
    public void logUserActionSafe(HttpServletRequest request) {
        String username = request.getParameter("username");
        String action = request.getParameter("action");
        
        // SAFE: Sanitize before logging
        String safeUsername = sanitizeLogInput(username);
        String safeAction = sanitizeLogInput(action);
        
        logger.info("User {} performed action: {}", safeUsername, safeAction);
    }

    // ============================================================
    // TRUE POSITIVE: Logging sensitive data
    // Severity: MEDIUM
    // ============================================================
    public void logAuthenticationVulnerable(String username, String password, boolean success) {
        // VULNERABLE: Logging password (even on failure) is a security issue
        if (success) {
            logger.info("User {} authenticated successfully", username);
        } else {
            logger.warn("Failed login attempt for user {} with password {}", username, password);
        }
    }

    // ============================================================
    // FALSE POSITIVE: Proper authentication logging
    // This should NOT be flagged
    // ============================================================
    public void logAuthenticationSafe(String username, String sourceIp, boolean success) {
        // SAFE: No sensitive data logged
        if (success) {
            logger.info("User {} authenticated from IP {}", 
                sanitizeLogInput(username), sanitizeLogInput(sourceIp));
        } else {
            logger.warn("Failed login attempt for user {} from IP {}", 
                sanitizeLogInput(username), sanitizeLogInput(sourceIp));
        }
    }

    // ============================================================
    // TRUE POSITIVE: Exception logging with user data
    // Severity: LOW
    // ============================================================
    public void processRequestVulnerable(HttpServletRequest request) {
        try {
            String data = request.getParameter("data");
            processData(data);
        } catch (Exception e) {
            // VULNERABLE: User input in exception message
            logger.error("Error processing request with data: " + 
                request.getParameter("data"), e);
        }
    }

    // ============================================================
    // FALSE POSITIVE: Exception logging without user data
    // This should NOT be flagged
    // ============================================================
    public void processRequestSafe(HttpServletRequest request) {
        String requestId = generateRequestId();
        try {
            String data = request.getParameter("data");
            processData(data);
        } catch (Exception e) {
            // SAFE: Only log request ID, not user data
            logger.error("Error processing request {}", requestId, e);
        }
    }

    private String sanitizeLogInput(String input) {
        if (input == null) {
            return "[null]";
        }
        // Remove newlines and control characters to prevent log forging
        return input.replaceAll("[\\r\\n\\t]", "_")
                   .replaceAll("[^\\x20-\\x7E]", "?");
    }

    private void processData(String data) {
        // Processing logic
    }

    private String generateRequestId() {
        return java.util.UUID.randomUUID().toString();
    }
}

